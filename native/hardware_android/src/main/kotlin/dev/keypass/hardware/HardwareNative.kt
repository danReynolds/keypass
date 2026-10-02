package dev.keypass.hardware

import android.app.Activity
import android.app.Application
import android.content.Context
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.startup.Initializer
import com.yubico.yubikit.core.application.CommandState
import org.json.JSONArray
import org.json.JSONObject
import java.lang.ref.WeakReference
import java.util.WeakHashMap
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.BlockingQueue
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class HardwareInitializer : Initializer<Unit> {
    override fun create(context: Context) { HardwareNative.install(context.applicationContext as Application) }
    override fun dependencies(): List<Class<out Initializer<*>>> = emptyList()
}
internal class HardwareOperation(val id: Long, owner: Activity, val request: HardwareRequest) {
    private val owner = WeakReference(owner)
    @Volatile var stopReason: String? = null
        private set
    @Volatile var waitingForUsbPermission = false
    @Volatile private var waitingForPin = false
    @Volatile private var connection: CloseOnce? = null
    val tagQueue = ArrayBlockingQueue<Tag>(1)
    val scanGeneration = AtomicInteger()
    private val pinQueue = ArrayBlockingQueue<ByteArray>(1)
    val state = object : CommandState() {
        override fun onKeepAliveStatus(status: Byte) {
            if (status == STATUS_UPNEEDED) emit("touch")
        }
    }
    fun activity(): Activity = owner.get()?.takeUnless { it.isDestroyed || it.isFinishing }
        ?: throw HardwareFailure("hostUnavailable")
    fun owns(activity: Activity) = owner.get() === activity
    fun check() {
        stopReason?.let { throw HardwareFailure(it) }
        if (!HardwareNative.pending(id)) throw HardwareFailure("cancelled")
    }
    fun emit(name: String, retries: Int? = null) {
        check()
        val json = JSONObject().put("event", name)
        retries?.let { json.put("attemptsRemaining", it) }
        if (!HardwareNative.emit(id, json)) throw HardwareFailure("backendFailure")
    }
    @Synchronized fun stop(code: String) {
        if (stopReason == null) stopReason = code
        waitingForPin = false
        pinQueue.poll()?.fill(0)
        state.cancel()
        connection?.let { lease -> HardwareNative.closeLater(lease) }
    }
    fun attach(lease: CloseOnce) {
        synchronized(this) { connection = lease }
        try { check() } catch (e: Exception) { detach(lease); throw e }
    }
    fun detach(lease: CloseOnce) {
        try { lease.close() }
        finally { synchronized(this) { if (connection === lease) connection = null } }
    }
    fun closeConnection() { connection?.let { detach(it) } }
    fun <T> await(queue: BlockingQueue<T>): T {
        while (true) {
            check()
            val value = queue.poll(50, TimeUnit.MILLISECONDS)
            if (value != null) return value
        }
    }
    @Synchronized fun submitPin(pin: ByteArray): Boolean {
        if (!waitingForPin || stopReason != null || pin.size !in 4..63 || pin.any { it == 0.toByte() }) return false
        val copy = pin.copyOf()
        if (pinQueue.offer(copy)) return true
        copy.fill(0); return false
    }
    fun requestPin(retries: Int): ByteArray {
        synchronized(this) { check(); waitingForPin = true }
        try { emit("pin", retries); return await(pinQueue) }
        finally { synchronized(this) { waitingForPin = false; pinQueue.poll()?.fill(0) } }
    }
    fun clear() {
        synchronized(this) { waitingForPin = false; pinQueue.poll()?.fill(0) }
        tagQueue.clear()
    }
}

/** AndroidX Startup registers host lifecycle; consumers never pass Activity handles. */
object HardwareNative : Application.ActivityLifecycleCallbacks {
    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor()
    private val closer = Executors.newSingleThreadExecutor()
    private val resumed = WeakHashMap<Activity, Boolean>()
    @Volatile private var active: HardwareOperation? = null
    private var installed = false

    @Synchronized internal fun install(application: Application) {
        if (installed) return
        System.loadLibrary("keypass_hardware")
        application.registerActivityLifecycleCallbacks(this)
        installed = true
    }
    @JvmStatic private external fun isPending(id: Long): Boolean
    @JvmStatic private external fun event(id: Long, metadata: ByteArray): Boolean
    @JvmStatic private external fun complete(id: Long, metadata: ByteArray, secret: ByteArray?, failed: Boolean)
    internal fun pending(id: Long) = isPending(id)
    internal fun emit(id: Long, metadata: JSONObject) = event(id, metadata.toString().toByteArray(Charsets.UTF_8))
    internal fun isActive(operation: HardwareOperation) = active === operation
    internal fun closeLater(lease: CloseOnce) { closer.execute { try { lease.close() } catch (_: Exception) {} } }
    internal fun <T> onMain(action: () -> T): T {
        if (Looper.myLooper() == Looper.getMainLooper()) return action()
        val result = CompletableFuture<T>()
        main.post {
            try { result.complete(action()) }
            catch (e: Exception) { result.completeExceptionally(e) }
        }
        return try { result.get(5, TimeUnit.SECONDS) }
        catch (e: java.util.concurrent.ExecutionException) { throw (e.cause as? Exception ?: e) }
    }
    private fun failure(id: Long, code: String) = complete(id,
        JSONObject().put("error", code).toString().toByteArray(Charsets.UTF_8), null, true)

    @JvmStatic fun submitPin(id: Long, pin: ByteArray): Boolean =
        active?.takeIf { it.id == id }?.submitPin(pin) ?: false

    @JvmStatic fun cancel(id: Long) {
        // Called from Dart's FFI thread; the operation owns its specific connection.
        active?.takeIf { it.id == id }?.stop("cancelled")
    }
    @JvmStatic fun dispatch(id: Long, bytes: ByteArray) { main.post {
        try {
            if (!isPending(id)) { failure(id, "cancelled"); return@post }
            if (active != null) { failure(id, "busy"); return@post }
            val activity = resumed.keys.singleOrNull()?.takeUnless { it.isFinishing || it.isDestroyed }
                ?: throw HardwareFailure("hostUnavailable")
            val request = HardwareRequest.parse(bytes)
            if (request.operation == "discover") {
                val devices = JSONArray()
                if (NfcAdapter.getDefaultAdapter(activity)?.isEnabled == true)
                    devices.put(JSONObject().put("id", NFC_READER_ID).put("name", "NFC security-key reader"))
                usbChoices(activity).forEachIndexed { index, choice ->
                    devices.put(JSONObject().put("id", choice.id).put("name", "USB FIDO candidate " + (index + 1)))
                }
                complete(id, JSONObject().put("devices", devices).toString().toByteArray(Charsets.UTF_8), null, false)
                return@post
            }
            // YubiKit's legacy no-op logger suppresses SDK tracing even if the
            // embedding app has installed an SLF4J provider. Never log payloads.
            @Suppress("DEPRECATION")
            com.yubico.yubikit.core.Logger.setLogger(object : com.yubico.yubikit.core.Logger() {})
            val operation = HardwareOperation(id, activity, request)
            active = operation
            val timeout = Runnable { if (active === operation) operation.stop("timeout") }
            main.postDelayed(timeout, 120000)
            worker.execute { execute(operation, timeout) }
        } catch (e: Exception) { failure(id, hardwareError(e)) }
    } }
    private fun execute(op: HardwareOperation, timeout: Runnable) {
        var response: HardwareResponse? = null
        var error: String? = null
        var pin: ByteArray? = null
        try {
            val transport = if (op.request.device == NFC_READER_ID) "nfc" else "usb"
            var retries: Int? = null
            withHardwareSession(op) { session ->
                checkCapabilities(session.cachedInfo, op.request.operation == "register")
                if (session.cachedInfo.options["uv"] == true) {
                    response = performHardware(op.request, session, null, op.state, op::check, transport)
                } else { retries = pinRetries(session) }
            }
            if (response == null) {
                pin = op.requestPin(retries ?: throw HardwareFailure("backendFailure"))
                withHardwareSession(op) { session ->
                    response = performHardware(op.request, session, pin, op.state, op::check, transport)
                }
            }
            op.check()
        } catch (e: Exception) { error = op.stopReason ?: hardwareError(e) }
        finally {
            pin?.fill(0)
            op.clear()
            try { op.closeConnection() } catch (_: Exception) { error = error ?: "deviceUnavailable" }
            try {
                onMain {
                    main.removeCallbacks(timeout)
                    if (active === op) active = null
                }
            } catch (_: Exception) { error = error ?: "hostUnavailable" }
            try {
                val result = response
                val code = op.stopReason ?: error
                if (code != null) failure(op.id, code)
                else if (result == null) failure(op.id, "backendFailure")
                else complete(op.id, result.metadata.toString().toByteArray(Charsets.UTF_8), result.secret, false)
            } finally { response?.clear() }
        }
    }
    override fun onActivityResumed(activity: Activity) { resumed[activity] = true }
    override fun onActivityPaused(activity: Activity) {
        resumed.remove(activity)
        active?.takeIf { it.owns(activity) && !it.waitingForUsbPermission }?.stop("cancelled")
    }
    override fun onActivityStopped(activity: Activity) { active?.takeIf { it.owns(activity) }?.stop("cancelled") }
    override fun onActivityDestroyed(activity: Activity) {
        resumed.remove(activity); active?.takeIf { it.owns(activity) }?.stop("cancelled")
    }
    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
    override fun onActivityStarted(activity: Activity) {}
    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
}
