package dev.keypass.hardware

import com.yubico.yubikit.core.Transport
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.fido.Cbor
import com.yubico.yubikit.fido.ctap.Ctap2Session
import com.yubico.yubikit.fido.webauthn.AuthenticatorData
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class ProtocolTest {
    private fun info(prf: Boolean = true, pin: Boolean = true, protect: Boolean = true): Map<Int, Any> = mapOf(
        1 to listOf("FIDO_2_0"), 2 to listOfNotNull(if (prf) "hmac-secret" else null, if (protect) "credProtect" else null),
        3 to ByteArray(16) { 0xa5.toByte() }, // Synthetic manufacturer; never allowlisted.
        4 to mapOf("rk" to true, "clientPin" to pin, "up" to true), 6 to listOf(1, 2)
    )
    private fun session(data: Map<Int, Any> = info()): Ctap2Session = Ctap2Session(ScriptedCard(data))
    private fun fails(code: String, action: () -> Unit) {
        try { action(); fail("Expected " + code) }
        catch (e: HardwareFailure) { assertEquals(code, e.code) }
    }
    @Test fun standardFidoSelectionAndCapabilitiesDoNotDependOnVendor() {
        val card = ScriptedCard(info())
        val session = Ctap2Session(card)
        checkCapabilities(session.cachedInfo, true)
        assertEquals(2, card.sent.size)
        assertArrayEquals(byteArrayOf(0, 0xa4.toByte(), 4, 0, 8, 0xa0.toByte(), 0, 0, 6, 0x47, 0x2f, 0, 1),
            card.sent[0].copyOf(13))
        assertArrayEquals(byteArrayOf(0x80.toByte(), 0x10, 0x80.toByte(), 0), card.sent[1].copyOf(4))
        assertEquals(2, pinProtocol(session.cachedInfo).version)
        fails("prfUnavailable") { checkCapabilities(session(info(prf = false)).cachedInfo, true) }
        fails("pinRequired") { checkCapabilities(session(info(pin = false)).cachedInfo, true) }
        fails("verificationUnavailable") { checkCapabilities(session(info(protect = false)).cachedInfo, true) }
    }
    @Test fun requestPreservesNormalizedSaltAndRejectsInvalidData() {
        val salt = ByteArray(32) { it.toByte() }
        val json = JSONObject().put("operation", "evaluate").put("device", NFC_READER_ID)
            .put("namespace", "dev.keypass.test").put("clientDataHash", encode(ByteArray(32)))
            .put("credentialId", encode(byteArrayOf(1))).put("hmacSalt", encode(salt))
        assertArrayEquals(salt, HardwareRequest.parse(json.toString().toByteArray()).salt)
        json.put("hmacSalt", "AA")
        fails("invalidRequest") { HardwareRequest.parse(json.toString().toByteArray()) }
        fails("invalidRequest") { HardwareRequest.parse("""{"operation":"reset"}""".toByteArray()) }
    }
    @Test fun usbReportsMustBelongToFidoAndHaveUnambiguousPacketShape() {
        val standard = byteArrayOf(6, 0xd0.toByte(), 0xf1.toByte(), 9, 1, 0xa1.toByte(), 1,
            9, 0x20, 0x15, 0, 0x26, 0xff.toByte(), 0, 0x75, 8, 0x95.toByte(), 64, 0x81.toByte(), 2,
            9, 0x21, 0x95.toByte(), 64, 0x91.toByte(), 2, 0xc0.toByte())
        assertTrue(isFidoReport(standard))
        val keyboard = standard.copyOf().apply { this[1] = 1; this[2] = 0 }
        assertFalse(isFidoReport(keyboard))
        assertFalse(isFidoReport(standard.copyOf(standard.size - 1)))
        assertFalse(isFidoReport(byteArrayOf(0xfe.toByte(), 0)))
        assertFalse(isFidoReport(standard + standard))
        assertFalse(isFidoReport(byteArrayOf(0x85.toByte(), 1) + standard))
        assertFalse(isFidoReport(standard.copyOf().apply { this[17] = 32 }))
    }
    @Test fun packedSelfAttestationBindsChallengeAndAuthenticatorData() {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val key = generator.generateKeyPair()
        val pub = key.public as ECPublicKey
        fun bytes(n: java.math.BigInteger): ByteArray {
            val encoded = n.toByteArray()
            val size = minOf(encoded.size, 32)
            return ByteArray(32).also { encoded.copyInto(it, 32 - size, encoded.size - size) }
        }
        val cose = mapOf(1 to 2, 3 to -7, -1 to 1, -2 to bytes(pub.w.affineX), -3 to bytes(pub.w.affineY))
        val rp = "dev.keypass.test"
        val hash = ByteArray(32) { 42 }
        val raw = MessageDigest.getInstance("SHA-256").digest(rp.toByteArray()) +
            byteArrayOf(0xc5.toByte(), 0, 0, 0, 1) + ByteArray(16) { 0xa5.toByte() } +
            byteArrayOf(0, 16) + ByteArray(16) { 2 } + Cbor.encode(cose) +
            Cbor.encode(mapOf("hmac-secret" to true, "credProtect" to 3))
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(key.private); signer.update(raw); signer.update(hash)
        val statement = mapOf("alg" to -7, "sig" to signer.sign())
        val auth = parseAuthenticator(raw, rp)
        verifyPacked("packed", statement, auth, hash)
        fails("verificationFailed") { verifyPacked("packed", statement, auth, ByteArray(32)) }
        val altered = raw.copyOf().apply { this[36] = 2 }
        fails("verificationFailed") { verifyPacked("packed", statement, parseAuthenticator(altered, rp), hash) }
        fails("verificationFailed") { verifyPacked("none", statement, auth, hash) }
        fails("verificationFailed") { parseAuthenticator(raw.copyOf().apply { this[32] = 0xc1.toByte() }, rp) }
    }
}
private class ScriptedCard(info: Map<Int, Any>) : SmartCardConnection {
    val sent = mutableListOf<ByteArray>()
    private val replies = java.util.ArrayDeque<ByteArray>().apply {
        add("U2F_V2".toByteArray() + byteArrayOf(0x90.toByte(), 0))
        add(byteArrayOf(0) + Cbor.encode(info) + byteArrayOf(0x90.toByte(), 0))
    }
    override fun sendAndReceive(apdu: ByteArray): ByteArray {
        sent.add(apdu.copyOf())
        check(replies.isNotEmpty()) { "Unexpected protocol operation" }
        return replies.removeFirst()
    }
    override fun getTransport() = Transport.NFC
    override fun isExtendedLengthApduSupported() = false
    override fun getAtr() = byteArrayOf()
    override fun close() {}
}
