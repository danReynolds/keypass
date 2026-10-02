package dev.keypass.hardware

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.*
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Build
import android.os.Bundle
import com.yubico.yubikit.core.Transport
import com.yubico.yubikit.core.fido.FidoConnection
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.fido.ctap.Ctap2Session
import java.io.Closeable
import java.io.IOException
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

internal const val NFC_READER_ID = "0000000000000000000000000000000000000000000000000000000000000001"
internal data class UsbChoice(val device: UsbDevice, val intf: UsbInterface, val input: UsbEndpoint, val output: UsbEndpoint) {
    val id: String get() = MessageDigest.getInstance("SHA-256")
        .digest(("Keypass Android USB v1\u0000" + device.deviceName + "\u0000" + intf.id).toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 255) }
}
internal fun usbChoices(context: Context): List<UsbChoice> {
    val manager = context.getSystemService(UsbManager::class.java) ?: return emptyList()
    return manager.deviceList.values.sortedBy { it.deviceName }.flatMap { device ->
        (0 until device.interfaceCount).mapNotNull { i ->
            val intf = device.getInterface(i)
            if (intf.interfaceClass != UsbConstants.USB_CLASS_HID || intf.interfaceSubclass != 0 || intf.interfaceProtocol != 0) return@mapNotNull null
            val endpoints = (0 until intf.endpointCount).map { intf.getEndpoint(it) }
            val input = endpoints.singleOrNull { it.type == UsbConstants.USB_ENDPOINT_XFER_INT && it.direction == UsbConstants.USB_DIR_IN && it.maxPacketSize == 64 }
            val output = endpoints.singleOrNull { it.type == UsbConstants.USB_ENDPOINT_XFER_INT && it.direction == UsbConstants.USB_DIR_OUT && it.maxPacketSize == 64 }
            if (input == null || output == null) null else UsbChoice(device, intf, input, output)
        }
    }.take(15)
}
internal class CloseOnce(private val value: Closeable) : Closeable {
    private var closed = false
    @Synchronized override fun close() {
        if (!closed) { closed = true; value.close() }
    }
}
private class NfcLink(private val tag: IsoDep, private val check: () -> Unit) : SmartCardConnection {
    private val closed = AtomicBoolean()
    fun connect() { check(); tag.connect(); if (closed.get()) { tag.close(); throw HardwareFailure("cancelled") }; tag.timeout = 3000; check() }
    override fun sendAndReceive(apdu: ByteArray): ByteArray {
        check()
        requireHardware(apdu.size <= 65544, "invalidRequest")
        val result = tag.transceive(apdu)
        check()
        requireHardware(result.size in 2..65538)
        return result
    }
    override fun getTransport() = Transport.NFC
    override fun isExtendedLengthApduSupported() = tag.isExtendedLengthApduSupported
    override fun getAtr(): ByteArray = tag.historicalBytes ?: tag.hiLayerResponse ?: byteArrayOf()
    override fun close() { if (closed.compareAndSet(false, true)) tag.close() }
}
private class UsbLink(private val connection: UsbDeviceConnection, private val choice: UsbChoice, private val check: () -> Unit) : FidoConnection {
    private val closed = AtomicBoolean()
    fun initialize() {
        check()
        val descriptor = ByteArray(1024)
        val count = connection.controlTransfer(0x81, 6, 0x2200, choice.intf.id, descriptor, descriptor.size, 1000)
        requireHardware(count > 0 && isFidoReport(descriptor.copyOf(count)), "verificationUnavailable")
        requireHardware(connection.claimInterface(choice.intf, true), "deviceUnavailable")
        check()
    }
    override fun send(packet: ByteArray) {
        check()
        requireHardware(packet.size == 64, "invalidRequest")
        if (connection.bulkTransfer(choice.output, packet, packet.size, 1000) != 64) throw IOException("USB send failed")
        check()
    }
    override fun receive(packet: ByteArray) {
        check()
        requireHardware(packet.size == 64, "invalidRequest")
        if (connection.bulkTransfer(choice.input, packet, packet.size, 1500) != 64) throw IOException("USB receive failed")
        check()
    }
    override fun close() {
        if (closed.compareAndSet(false, true)) {
            try { connection.releaseInterface(choice.intf) } finally { connection.close() }
        }
    }
}
internal fun <T> withHardwareSession(op: HardwareOperation, body: (Ctap2Session) -> T): T =
    if (op.request.device == NFC_READER_ID) withNfcSession(op, body) else withUsbSession(op, body)

private fun <T> withNfcSession(op: HardwareOperation, body: (Ctap2Session) -> T): T {
    val activity = op.activity()
    val adapter = NfcAdapter.getDefaultAdapter(activity)
    requireHardware(adapter?.isEnabled == true, "deviceUnavailable")
    op.tagQueue.clear()
    val generation = op.scanGeneration.incrementAndGet()
    HardwareNative.onMain {
        op.check()
        adapter!!.enableReaderMode(activity, { tag ->
            if (HardwareNative.isActive(op) && op.stopReason == null && op.scanGeneration.get() == generation) op.tagQueue.offer(tag)
        }, NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
            Bundle().apply { putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250) })
    }
    var observedTag: Tag? = null
    try {
        // Only invite a scan after Android has installed the reader callback.
        op.emit("presentKey")
        val tag = op.await(op.tagQueue)
        observedTag = tag
        val iso = IsoDep.get(tag) ?: throw HardwareFailure("verificationUnavailable")
        val link = NfcLink(iso, op::check)
        val lease = CloseOnce(link)
        op.attach(lease)
        try { link.connect(); return body(Ctap2Session(link)) }
        finally { op.detach(lease) }
    } finally {
        op.scanGeneration.incrementAndGet()
        HardwareNative.onMain {
            if (HardwareNative.isActive(op)) {
                // Suppress normal NDEF/URL redispatch while this tag remains in
                // range after connection cleanup, including failed operations.
                // No tag contents or vendor-specific configuration is changed.
                try { observedTag?.let { adapter!!.ignore(it, 500, null, null) } }
                finally { adapter!!.disableReaderMode(activity) }
            }
        }
        op.tagQueue.clear()
    }
}
private fun requestUsbPermission(op: HardwareOperation, manager: UsbManager, choice: UsbChoice) {
    if (manager.hasPermission(choice.device)) return
    val activity = op.activity()
    val action = activity.packageName + ".keypass.USB." + UUID.randomUUID()
    val queue = java.util.concurrent.ArrayBlockingQueue<Boolean>(1)
    val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == action && HardwareNative.isActive(op))
                queue.offer(manager.hasPermission(choice.device)) // Check OS permission, not broadcast extras.
        }
    }
    var registered = false
    var intent: PendingIntent? = null
    op.waitingForUsbPermission = true
    try {
        HardwareNative.onMain {
            op.check()
            if (Build.VERSION.SDK_INT >= 33) activity.registerReceiver(receiver, IntentFilter(action), Context.RECEIVER_NOT_EXPORTED)
            else @Suppress("DEPRECATION") activity.registerReceiver(receiver, IntentFilter(action))
            registered = true
            intent = PendingIntent.getBroadcast(activity, 0, Intent(action).setPackage(activity.packageName), PendingIntent.FLAG_IMMUTABLE)
            manager.requestPermission(choice.device, intent!!)
        }
        requireHardware(op.await(queue), "cancelled")
        requireHardware(manager.hasPermission(choice.device), "hostUnavailable")
    } finally {
        HardwareNative.onMain {
            if (registered) activity.unregisterReceiver(receiver)
            intent?.cancel()
            op.waitingForUsbPermission = false
        }
    }
}
private fun <T> withUsbSession(op: HardwareOperation, body: (Ctap2Session) -> T): T {
    val activity = op.activity()
    val manager = activity.getSystemService(UsbManager::class.java)
    val choice = usbChoices(activity).singleOrNull { it.id == op.request.device } ?: throw HardwareFailure("deviceUnavailable")
    requestUsbPermission(op, manager, choice)
    op.check()
    val connection = manager.openDevice(choice.device) ?: throw HardwareFailure("deviceUnavailable")
    val link = UsbLink(connection, choice, op::check)
    val lease = CloseOnce(link)
    op.attach(lease)
    try { link.initialize(); return body(Ctap2Session(link)) }
    finally { op.detach(lease) }
}
