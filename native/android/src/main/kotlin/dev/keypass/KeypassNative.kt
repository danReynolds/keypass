package dev.keypass

import android.app.Activity
import android.app.Application
import android.content.Context
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.util.Base64
import androidx.credentials.*
import androidx.credentials.exceptions.*
import androidx.startup.Initializer
import org.json.JSONObject
import java.lang.ref.WeakReference
import java.security.MessageDigest
import java.util.WeakHashMap
import java.util.concurrent.Executor

/** Installed once by manifest merging; Dart callers never pass an Activity. */
class KeypassInitializer : Initializer<Unit> {
    override fun create(context: Context) { KeypassNative.install(context.applicationContext as Application) }
    override fun dependencies(): List<Class<out Initializer<*>>> = emptyList()
}

object KeypassNative : Application.ActivityLifecycleCallbacks {
    private val main = Handler(Looper.getMainLooper())
    private val executor = Executor { main.post(it) }
    private val resumed = WeakHashMap<Activity, Boolean>()
    private data class Operation(val id: Long, val owner: WeakReference<Activity>, val cancellation: CancellationSignal, val timeout: Runnable, val fence: CompletionFence = CompletionFence())
    private var active: Operation? = null
    private var installed = false
    internal fun install(application: Application) {
        if (installed) return
        System.loadLibrary("keypass")
        application.registerActivityLifecycleCallbacks(this)
        installed = true
    }
    @JvmStatic private external fun isPending(id: Long): Boolean
    @JvmStatic private external fun complete(id: Long, metadata: ByteArray, secret: ByteArray?, error: Boolean)
    private fun error(id: Long, code: String) = complete(id, JSONObject().put("error", code).toString().toByteArray(Charsets.UTF_8), null, true)
    private fun finish(id: Long, metadata: JSONObject, secret: ByteArray? = null) {
        try { complete(id, metadata.toString().toByteArray(Charsets.UTF_8), secret, false) }
        finally { secret?.fill(0) }
    }
    private fun end(id: Long): Boolean {
        val operation = active ?: return false
        if (operation.id != id) return false
        main.removeCallbacks(operation.timeout)
        active = null
        return operation.fence.finish()
    }
    private fun stop(id: Long, code: String) {
        val operation = active?.takeIf { it.id == id } ?: return
        if (!operation.fence.cancel()) return
        main.removeCallbacks(operation.timeout)
        // Keep active until the framework callback arrives. CancellationSignal
        // has no join operation; a new ceremony must remain busy meanwhile.
        operation.cancellation.cancel()
        error(id, code)
    }
    @JvmStatic fun cancel(id: Long) { main.post { stop(id, "cancelled") } }
    @JvmStatic fun dispatch(id: Long, bytes: ByteArray) { main.post {
        try {
            if (!isPending(id)) return@post
            if (active != null) { error(id, "busy"); return@post }
            val activity = resumed.keys.singleOrNull()?.takeUnless { it.isFinishing || it.isDestroyed }
            if (activity == null) { error(id, "hostUnavailable"); return@post }
            val request = JSONObject(bytes.toString(Charsets.UTF_8))
            if (request.getString("operation") == "availability") {
                val info = activity.packageManager.getPackageInfo(activity.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                val signatures = info.signingInfo?.apkContentsSigners
                if (signatures?.size != 1) { error(id, "hostUnavailable"); return@post }
                val hash = MessageDigest.getInstance("SHA-256").digest(signatures[0].toByteArray())
                val origin = "android:apk-key-hash:" + Base64.encodeToString(hash, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
                finish(id, JSONObject().put("platform", "android").put("origin", origin).put("multiple", true))
                return@post
            }
            val options = request.getJSONObject("publicKey").toString()
            val manager = CredentialManager.create(activity)
            val cancellation = CancellationSignal()
            val timeout = Runnable {
                stop(id, "timeout")
            }
            active = Operation(id, WeakReference(activity), cancellation, timeout)
            main.postDelayed(timeout, 120000)
            when (request.getString("operation")) {
                "register" -> manager.createCredentialAsync(activity,
                    CreatePublicKeyCredentialRequest(requestJson = options), cancellation, executor,
                    object : CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException> {
                        override fun onResult(result: CreateCredentialResponse) {
                            if (!end(id)) return
                            val response = result as? CreatePublicKeyCredentialResponse
                            if (response == null) { error(id, "verificationFailed"); return }
                            consume(id, response.registrationResponseJson, true)
                        }
                        override fun onError(e: CreateCredentialException) {
                            if (end(id)) error(id, when (e) {
                                is CreateCredentialCancellationException -> "cancelled"
                                is CreateCredentialProviderConfigurationException, is CreateCredentialUnsupportedException -> "backendUnavailable"
                                else -> "backendFailure"
                            })
                        }
                    })
                "evaluate" -> manager.getCredentialAsync(activity,
                    GetCredentialRequest(listOf(GetPublicKeyCredentialOption(options))), cancellation, executor,
                    object : CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
                        override fun onResult(result: GetCredentialResponse) {
                            if (!end(id)) return
                            val response = result.credential as? PublicKeyCredential
                            if (response == null) { error(id, "verificationFailed"); return }
                            consume(id, response.authenticationResponseJson, false)
                        }
                        override fun onError(e: GetCredentialException) {
                            if (end(id)) error(id, when (e) {
                                is GetCredentialCancellationException -> "cancelled"
                                is NoCredentialException -> "credentialUnavailable"
                                is GetCredentialProviderConfigurationException, is GetCredentialUnsupportedException -> "backendUnavailable"
                                else -> "backendFailure"
                            })
                        }
                    })
                else -> { end(id); error(id, "invalidRequest") }
            }
        } catch (_: Exception) { end(id); error(id, "backendFailure") }
    } }
    private fun consume(id: Long, json: String, registration: Boolean) {
        var secret: ByteArray? = null
        try {
            require(json.length <= 65536)
            val value = JSONObject(json)
            require(value.getString("type") == "public-key")
            val response = value.getJSONObject("response")
            val metadata = JSONObject().put("credentialId", value.getString("rawId"))
                .put("clientDataJSON", response.getString("clientDataJSON"))
            val prf = value.optJSONObject("clientExtensionResults")?.optJSONObject("prf")
            if (registration) {
                metadata.put("attestationObject", response.getString("attestationObject"))
                    .put("prfEnabled", prf?.optBoolean("enabled", false) == true)
            } else {
                metadata.put("authenticatorData", response.getString("authenticatorData"))
                    .put("signature", response.getString("signature"))
                if (!response.isNull("userHandle")) metadata.put("userHandle", response.getString("userHandle"))
                val first = prf?.optJSONObject("results")?.optString("first")
                if (first.isNullOrEmpty() || first.length > 44) { error(id, "prfUnavailable"); return }
                secret = Base64.decode(first, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
                if (secret.size != 32) { error(id, "prfUnavailable"); return }
            }
            finish(id, metadata, secret)
        } catch (_: Exception) { error(id, "verificationFailed") }
        finally { secret?.fill(0) }
        // Credential Manager owns an immutable JSON String containing PRF output.
        // We cannot erase that framework allocation; never retain or log it.
    }
    override fun onActivityResumed(activity: Activity) { resumed[activity] = true }
    override fun onActivityPaused(activity: Activity) { resumed.remove(activity) }
    override fun onActivityDestroyed(activity: Activity) {
        resumed.remove(activity)
        active?.takeIf { it.owner.get() === activity }?.let { cancel(it.id) }
    }
    override fun onActivityCreated(activity: Activity, state: Bundle?) {}
    override fun onActivityStarted(activity: Activity) {}
    override fun onActivityStopped(activity: Activity) {}
    override fun onActivitySaveInstanceState(activity: Activity, state: Bundle) {}
}
