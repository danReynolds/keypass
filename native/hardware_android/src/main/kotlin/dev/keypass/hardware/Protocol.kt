package dev.keypass.hardware

import com.yubico.yubikit.core.application.CommandState
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.fido.Cose
import com.yubico.yubikit.fido.ctap.ClientPin
import com.yubico.yubikit.fido.ctap.Ctap2Session
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2
import com.yubico.yubikit.fido.webauthn.AuthenticatorData
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.AlgorithmParameters
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.text.Normalizer
import java.util.Base64

internal class HardwareFailure(val code: String) : Exception(code)
internal fun requireHardware(value: Boolean, code: String = "verificationFailed") {
    if (!value) throw HardwareFailure(code)
}
internal fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
internal fun decode(value: String, maximum: Int): ByteArray {
    requireHardware(value.isNotEmpty() && value.length <= 4 * ((maximum + 2) / 3) &&
        value.matches(Regex("[A-Za-z0-9_-]+")), "invalidRequest")
    val result = try { Base64.getUrlDecoder().decode(value) } catch (_: IllegalArgumentException) {
        throw HardwareFailure("invalidRequest")
    }
    requireHardware(result.size <= maximum && encode(result) == value, "invalidRequest")
    return result
}
internal data class HardwareRequest(
    val operation: String, val device: String = "", val namespace: String = "",
    val hash: ByteArray = byteArrayOf(), val credential: ByteArray = byteArrayOf(),
    val salt: ByteArray = byteArrayOf(), val user: ByteArray = byteArrayOf(),
    val displayName: String = "", val label: String = ""
) {
    companion object {
        fun parse(bytes: ByteArray): HardwareRequest {
            try {
                requireHardware(bytes.size in 1..65536, "invalidRequest")
                val json = JSONObject(bytes.toString(Charsets.UTF_8))
                val operation = json.getString("operation")
                requireHardware(operation in listOf("discover", "register", "evaluate"), "invalidRequest")
                if (operation == "discover") return HardwareRequest(operation)
                val device = json.getString("device")
                val namespace = json.getString("namespace")
                requireHardware(device.matches(Regex("[0-9a-f]{64}")) &&
                    namespace.length in 1..253 && namespace.matches(Regex("[a-z0-9.-]+")), "invalidRequest")
                val hash = decode(json.getString("clientDataHash"), 32)
                requireHardware(hash.size == 32, "invalidRequest")
                if (operation == "evaluate") {
                    val credential = decode(json.getString("credentialId"), 1024)
                    val salt = decode(json.getString("hmacSalt"), 32)
                    requireHardware(salt.size == 32, "invalidRequest")
                    return HardwareRequest(operation, device, namespace, hash, credential, salt)
                }
                val user = decode(json.getString("userId"), 64)
                val name = json.getString("displayName")
                val label = json.getString("label")
                requireHardware(listOf(name, label).all { it.isNotEmpty() &&
                    it.toByteArray(Charsets.UTF_8).size <= 1024 && !it.contains('\u0000') }, "invalidRequest")
                return HardwareRequest(operation, device, namespace, hash, user = user, displayName = name, label = label)
            } catch (e: HardwareFailure) { throw e }
            catch (_: Exception) { throw HardwareFailure("invalidRequest") }
        }
    }
}
internal class HardwareResponse(val metadata: JSONObject, val secret: ByteArray? = null) {
    fun clear() { secret?.fill(0) }
}
internal fun checkCapabilities(info: Ctap2Session.InfoData, registration: Boolean) {
    requireHardware(info.versions.any { it.startsWith("FIDO_2_") }, "verificationUnavailable")
    requireHardware(info.extensions.contains("hmac-secret"), "prfUnavailable")
    requireHardware(!info.forcePinChange, "pinChangeRequired")
    requireHardware(info.options["uv"] == true || info.options["clientPin"] == true, "pinRequired")
    if (registration) requireHardware(info.options["rk"] == true && info.extensions.contains("credProtect"),
        "verificationUnavailable")
}
internal fun pinProtocol(info: Ctap2Session.InfoData): PinUvAuthProtocol = when {
    info.pinUvAuthProtocols.contains(2) -> PinUvAuthProtocolV2()
    info.pinUvAuthProtocols.contains(1) -> PinUvAuthProtocolV1()
    else -> throw HardwareFailure("verificationUnavailable")
}
internal fun pinRetries(session: Ctap2Session): Int {
    val retries = ClientPin(session, pinProtocol(session.cachedInfo)).pinRetries
    requireHardware(retries.powerCycleState != true, "pinTemporarilyBlocked")
    requireHardware(retries.count > 0, "pinBlocked")
    requireHardware(retries.count <= 255, "verificationFailed")
    return retries.count
}
internal fun parseAuthenticator(bytes: ByteArray, namespace: String): AuthenticatorData {
    requireHardware(bytes.size in 37..8192)
    val buffer = ByteBuffer.wrap(bytes)
    val result = AuthenticatorData.parseFrom(buffer)
    requireHardware(!buffer.hasRemaining() && result.isUp && result.isUv &&
        (result.flags.toInt() and 0x18) == 0 &&
        MessageDigest.isEqual(result.rpIdHash, MessageDigest.getInstance("SHA-256").digest(namespace.toByteArray(Charsets.UTF_8))))
    return result
}
internal fun verifyPacked(format: String, statement: Map<String, *>, auth: AuthenticatorData, hash: ByteArray) {
    requireHardware(format == "packed" && statement["alg"] == -7 && statement["ecdaaKeyId"] == null)
    val signature = statement["sig"] as? ByteArray ?: throw HardwareFailure("verificationFailed")
    requireHardware(signature.size in 8..72)
    val credential = auth.attestedCredentialData ?: throw HardwareFailure("verificationFailed")
    val cose = credential.cosePublicKey
    requireHardware(cose[1] == 2 && cose[3] == -7 && cose[-1] == 1)
    val certificates = statement["x5c"]
    val key = if (certificates == null) {
        Cose.getPublicKey(cose)
    } else {
        requireHardware(certificates is List<*> && certificates.size in 1..8)
        val cert = (certificates as List<*>)[0] as? ByteArray ?: throw HardwareFailure("verificationFailed")
        requireHardware(cert.size in 1..16384)
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(cert)).publicKey
    }
    val parameters = AlgorithmParameters.getInstance("EC")
    parameters.init(ECGenParameterSpec("secp256r1"))
    val p256 = parameters.getParameterSpec(ECParameterSpec::class.java)
    requireHardware(key is ECPublicKey && key.params.order == p256.order && key.params.curve == p256.curve &&
        key.params.generator == p256.generator && key.params.cofactor == p256.cofactor)
    val verifier = Signature.getInstance("SHA256withECDSA")
    verifier.initVerify(key)
    verifier.update(auth.bytes)
    verifier.update(hash)
    requireHardware(verifier.verify(signature))
}
internal fun pinChars(pin: ByteArray): CharArray {
    val decoder = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
    val buffer = decoder.decode(ByteBuffer.wrap(pin))
    try {
        // Normalizer returns an immutable String; see documented JVM memory limits.
        val normalized = Normalizer.normalize(buffer, Normalizer.Form.NFC).toCharArray()
        try {
            requireHardware(Character.codePointCount(normalized, 0, normalized.size) >= 4, "invalidRequest")
            return normalized
        } catch (e: Exception) {
            normalized.fill('\u0000')
            throw e
        }
    } finally { if (buffer.hasArray()) buffer.array().fill('\u0000') }
}
internal fun performHardware(
    request: HardwareRequest, session: Ctap2Session, pin: ByteArray?,
    state: CommandState, check: () -> Unit, transport: String
): HardwareResponse {
    check()
    val info = session.cachedInfo
    checkCapabilities(info, request.operation == "register")
    val protocol = pinProtocol(info)
    val client = ClientPin(session, protocol)
    val permission = if (request.operation == "register") ClientPin.PIN_PERMISSION_MC else ClientPin.PIN_PERMISSION_GA
    var token: ByteArray? = null
    var authorization: ByteArray? = null
    try {
        if (pin != null) {
            requireHardware(info.options["clientPin"] == true, "pinRequired")
            val chars = pinChars(pin)
            try { token = client.getPinToken(chars, permission, request.namespace) }
            finally { chars.fill('\u0000') }
        } else {
            requireHardware(info.options["uv"] == true, "verificationUnavailable")
            if (ClientPin.isTokenSupported(info)) token = client.getUvToken(permission, request.namespace, state)
        }
        check()
        authorization = token?.let { protocol.authenticate(it, request.hash) }
        val options = mutableMapOf<String, Any>()
        if (token == null) options["uv"] = true // Token-authenticated requests omit uv.
        if (request.operation == "register") {
            options["rk"] = true
            val result = session.makeCredential(request.hash,
                mapOf("id" to request.namespace, "name" to request.displayName),
                mapOf("id" to request.user, "name" to request.label, "displayName" to request.label),
                listOf(mapOf("type" to "public-key", "alg" to -7)), null,
                mapOf("hmac-secret" to true, "credProtect" to 3), options,
                authorization, if (authorization == null) null else protocol.version, null, state)
            check()
            val auth = parseAuthenticator(result.authenticatorData, request.namespace)
            verifyPacked(result.format, result.attestationStatement, auth, request.hash)
            requireHardware(auth.extensions?.get("hmac-secret") == true && auth.extensions?.get("credProtect") == 3)
            val credential = auth.attestedCredentialData ?: throw HardwareFailure("verificationFailed")
            requireHardware(credential.credentialId.size in 1..1024)
            return HardwareResponse(JSONObject().put("attestationVerified", true)
                .put("transports", org.json.JSONArray(listOf(transport)))
                .put("credentialId", encode(credential.credentialId))
                .put("authenticatorData", encode(result.authenticatorData)))
        }
        // Dart supplied the 32-byte, already-normalized WebAuthn PRF salt.
        val agreement = client.sharedSecret
        try {
            val encryptedSalt = protocol.encrypt(agreement.second, request.salt)
            val saltAuth = protocol.authenticate(agreement.second, encryptedSalt)
            options["up"] = true
            val result = session.getAssertions(request.namespace, request.hash,
                listOf(mapOf("type" to "public-key", "id" to request.credential)),
                mapOf("hmac-secret" to mapOf(1 to agreement.first, 2 to encryptedSalt, 3 to saltAuth, 4 to protocol.version)),
                options, authorization, if (authorization == null) null else protocol.version, state)
            check()
            requireHardware(result.size == 1)
            val assertion = result.single()
            requireHardware((assertion.numberOfCredentials ?: 1) == 1 && assertion.signature.size in 8..72)
            val id = assertion.credential?.get("id") as? ByteArray ?: request.credential
            requireHardware(MessageDigest.isEqual(id, request.credential))
            val auth = parseAuthenticator(assertion.authenticatorData, request.namespace)
            val encrypted = auth.extensions?.get("hmac-secret") as? ByteArray ?: throw HardwareFailure("prfUnavailable")
            requireHardware(encrypted.size == if (protocol.version == 1) 32 else 48, "prfUnavailable")
            val secret = protocol.decrypt(agreement.second, encrypted)
            try {
                requireHardware(secret.size == 32, "prfUnavailable")
                check()
                val metadata = JSONObject().put("credentialId", encode(id))
                    .put("authenticatorData", encode(assertion.authenticatorData))
                    .put("signature", encode(assertion.signature))
                assertion.user?.get("id")?.let {
                    requireHardware(it is ByteArray && it.size in 1..64)
                    metadata.put("userHandle", encode(it as ByteArray))
                }
                return HardwareResponse(metadata, secret.copyOf())
            } finally { secret.fill(0) }
        } finally { agreement.second.fill(0) }
    } finally { token?.fill(0); authorization?.fill(0) }
}
internal fun hardwareError(error: Exception): String = when (error) {
    is HardwareFailure -> error.code
    is InterruptedException -> "cancelled"
    is CtapException -> when (error.ctapError) {
        CtapException.ERR_PIN_INVALID -> "pinInvalid"
        CtapException.ERR_PIN_BLOCKED -> "pinBlocked"
        CtapException.ERR_PIN_AUTH_BLOCKED -> "pinTemporarilyBlocked"
        CtapException.ERR_PIN_NOT_SET, CtapException.ERR_PUAT_REQUIRED -> "pinRequired"
        CtapException.ERR_UV_BLOCKED, CtapException.ERR_UV_INVALID,
        CtapException.ERR_UNSUPPORTED_OPTION, CtapException.ERR_UNAUTHORIZED_PERMISSION -> "verificationUnavailable"
        CtapException.ERR_KEEPALIVE_CANCEL, CtapException.ERR_OPERATION_DENIED -> "cancelled"
        CtapException.ERR_KEY_STORE_FULL -> "credentialStorageFull"
        CtapException.ERR_NO_CREDENTIALS, CtapException.ERR_INVALID_CREDENTIAL -> "credentialUnavailable"
        CtapException.ERR_TIMEOUT, CtapException.ERR_ACTION_TIMEOUT, CtapException.ERR_USER_ACTION_TIMEOUT -> "timeout"
        CtapException.ERR_UNSUPPORTED_EXTENSION -> "prfUnavailable"
        else -> "backendFailure"
    }
    is IOException -> "deviceUnavailable"
    is SecurityException -> "hostUnavailable"
    else -> "backendFailure"
}
