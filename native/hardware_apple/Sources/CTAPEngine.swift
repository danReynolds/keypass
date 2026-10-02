import Foundation
import CryptoKit
import Security
import YubiKit

let nfcReaderID = String(repeating: "0", count: 63) + "1" // Reader, not a credential/device identity.

struct HardwareRequest {
    let operation: String
    let namespace: String
    let hash: Data
    let credential: Data
    let salt: Data
    let user: Data
    let displayName: String
    let label: String
    init(_ json: [String: Any]) throws {
        guard let operation = json["operation"] as? String,
              ["discover", "register", "evaluate"].contains(operation) else { throw HardwareFailure.code("invalidRequest") }
        self.operation = operation
        if operation == "discover" {
            namespace = ""; hash = Data(); credential = Data(); salt = Data(); user = Data(); displayName = ""; label = ""
            return
        }
        guard json["device"] as? String == nfcReaderID,
              let namespace = json["namespace"] as? String, !namespace.isEmpty, namespace.utf8.count <= 253,
              namespace.range(of: "^[a-z0-9.-]+$", options: .regularExpression) != nil else {
            throw HardwareFailure.code("invalidRequest")
        }
        self.namespace = namespace
        hash = try hardwareBytes(json["clientDataHash"], maximum: 32)
        guard hash.count == 32 else { throw HardwareFailure.code("invalidRequest") }
        if operation == "evaluate" {
            credential = try hardwareBytes(json["credentialId"], maximum: 1024)
            salt = try hardwareBytes(json["hmacSalt"], maximum: 32)
            guard salt.count == 32 else { throw HardwareFailure.code("invalidRequest") }
            user = Data(); displayName = ""; label = ""
        } else {
            user = try hardwareBytes(json["userId"], maximum: 64)
            guard let display = json["displayName"] as? String, !display.isEmpty, display.utf8.count <= 1024,
                  let label = json["label"] as? String, !label.isEmpty, label.utf8.count <= 1024,
                  !display.contains("\0"), !label.contains("\0") else { throw HardwareFailure.code("invalidRequest") }
            displayName = display; self.label = label; credential = Data(); salt = Data()
        }
    }
}
func hardwareBase64(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}
func hardwareBytes(_ object: Any?, maximum: Int) throws -> Data {
    guard let text = object as? String, !text.isEmpty, text.utf8.count <= 4 * ((maximum + 2) / 3),
          text.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil else { throw HardwareFailure.code("invalidRequest") }
    var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
    guard let data = Data(base64Encoded: base64), data.count <= maximum, hardwareBase64(data) == text else {
        throw HardwareFailure.code("invalidRequest")
    }
    return data
}
struct HardwareResponse {
    let metadata: [String: Any]
    var secret: Data?
    mutating func clear() { if secret != nil { secret!.resetBytes(in: 0..<secret!.count); secret = nil } }
}

func checkHardwareInfo(_ info: CTAP2.GetInfo.Response, registration: Bool) throws {
    guard info.extensions.contains(.hmacSecret) else { throw HardwareFailure.code("prfUnavailable") }
    guard info.forcePinChange != true else { throw HardwareFailure.code("pinChangeRequired") }
    guard info.options.userVerification == true || info.options.clientPin == true else { throw HardwareFailure.code("pinRequired") }
    if registration && (!info.options.residentKey || !info.extensions.contains(.credProtect)) {
        throw HardwareFailure.code("verificationUnavailable")
    }
}

func hardwareErrorCode(_ error: Error) -> String {
    if error is CancellationError { return "cancelled" }
    if case HardwareFailure.code(let code) = error { return code }
    if let error = error as? SmartCardConnectionError {
        switch error {
        case .cancelled, .cancelledByUser: return "cancelled"
        case .unsupported: return "backendUnavailable"
        case .busy: return "busy"
        case .connectionLost, .noDevicesFound: return "deviceUnavailable"
        case .setupFailed(_, let inner), .transmitFailed(_, let inner):
            if let inner { return hardwareErrorCode(inner) }
            return "deviceUnavailable"
        default: return "backendFailure"
        }
    }
    if let error = error as? CTAP2.SessionError {
        switch error {
        case .connectionError(let inner, _): return hardwareErrorCode(inner)
        case .timeout: return "timeout"
        case .extensionNotSupported: return "prfUnavailable"
        case .featureNotSupported: return "verificationUnavailable"
        case .ctapError(let code, _):
            switch code {
            case .pinInvalid: return "pinInvalid"
            case .pinBlocked: return "pinBlocked"
            case .pinAuthBlocked: return "pinTemporarilyBlocked"
            case .pinNotSet, .puatRequired: return "pinRequired"
            case .uvBlocked, .uvInvalid: return "verificationUnavailable"
            case .keepaliveCancel, .operationDenied: return "cancelled"
            case .keyStoreFull: return "credentialStorageFull"
            case .noCredentials, .invalidCredential: return "credentialUnavailable"
            case .actionTimeout, .userActionTimeout: return "timeout"
            default: return "backendFailure"
            }
        default: return "backendFailure"
        }
    }
    return "backendFailure"
}

/// Native enrollment evidence: packed ES256 certificate or self-attestation.
/// This verifies a signature, not a certificate chain or manufacturer identity.
func verifyHardwarePacked(_ response: CTAP2.MakeCredential.Response, hash: Data) throws {
    guard case .packed(let statement) = response.attestationObject.statement,
          statement.alg == -7, statement.ecdaaKeyId == nil,
          let credential = response.authenticatorData.attestedCredentialData else {
        throw HardwareFailure.code("verificationFailed")
    }
    let key: SecKey
    if let certificates = statement.x5c, !certificates.isEmpty {
        guard certificates.count <= 8, certificates[0].count <= 16384,
              let certificate = SecCertificateCreateWithData(nil, certificates[0] as CFData),
              let publicKey = SecCertificateCopyKey(certificate) else { throw HardwareFailure.code("verificationFailed") }
        key = publicKey
    } else {
        guard case .ec2(let algorithm, _, let curve, let x, let y) = credential.credentialPublicKey,
              algorithm == .es256, curve == 1, x.count == 32, y.count == 32,
              let publicKey = SecKeyCreateWithData((Data([4]) + x + y) as CFData, [
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass: kSecAttrKeyClassPublic,
                kSecAttrKeySizeInBits: 256,
              ] as CFDictionary, nil) else { throw HardwareFailure.code("verificationFailed") }
        key = publicKey
    }
    guard SecKeyIsAlgorithmSupported(key, .verify, .ecdsaSignatureMessageX962SHA256),
          SecKeyVerifySignature(key, .ecdsaSignatureMessageX962SHA256,
                                (response.authenticatorData.rawData + hash) as CFData,
                                statement.sig as CFData, nil) else { throw HardwareFailure.code("verificationFailed") }
}

func performHardwareRequest(_ request: HardwareRequest, session: CTAP2.Session,
                            token: CTAP2.Token?) async throws -> HardwareResponse {
    if request.operation == "register" {
        let protection = try await CTAP2.Extension.CredProtect(level: .userVerificationRequired, session: session, enforce: true)
        let hmac = CTAP2.Extension.HmacSecret()
        let response = try await session.makeCredential(parameters: .init(
            clientDataHash: request.hash,
            rp: .init(id: request.namespace, name: request.displayName),
            user: .init(id: request.user, name: request.label, displayName: request.label),
            pubKeyCredParams: [.es256], extensions: [hmac.makeCredential.input(), protection.input()],
            rk: true, uv: true
        ), token: token).value
        try Task.checkCancellation()
        try verifyHardwarePacked(response, hash: request.hash)
        guard response.authenticatorData.flags.contains([.userPresent, .userVerified]),
              protection.output(from: response) == .userVerificationRequired,
              let credential = response.authenticatorData.attestedCredentialData,
              credential.credentialId.count <= 1024, response.authenticatorData.rawData.count <= 8192 else {
            throw HardwareFailure.code("verificationFailed")
        }
        return HardwareResponse(metadata: [
            "attestationVerified": true, "transports": ["nfc"],
            "credentialId": hardwareBase64(credential.credentialId),
            "authenticatorData": hardwareBase64(response.authenticatorData.rawData)
        ])
    }
    // Dart already applied WebAuthn's normalization. Never hash this salt again.
    let hmac = try await CTAP2.Extension.HmacSecret(session: session)
    let response = try await session.getAssertion(parameters: .init(
        rpId: request.namespace, clientDataHash: request.hash,
        allowList: [.init(id: request.credential)],
        extensions: [try hmac.getAssertion.input(salt1: request.salt)], up: true, uv: true
    ), token: token).value
    try Task.checkCancellation()
    guard (response.numberOfCredentials ?? 1) == 1,
          response.authenticatorData.flags.contains([.userPresent, .userVerified]),
          response.authenticatorData.rawData.count <= 8192, response.signature.count <= 72,
          response.credential == nil || response.credential!.id == request.credential else {
        throw HardwareFailure.code("verificationFailed")
    }
    guard var secret = try hmac.getAssertion.output(from: response)?.first,
          secret.count == 32 else { throw HardwareFailure.code("prfUnavailable") }
    defer { secret.resetBytes(in: 0..<secret.count) }
    var metadata: [String: Any] = [
        "credentialId": hardwareBase64(response.credential?.id ?? request.credential),
        "authenticatorData": hardwareBase64(response.authenticatorData.rawData),
        "signature": hardwareBase64(response.signature)
    ]
    if let user = response.user { metadata["userHandle"] = hardwareBase64(user.id) }
    // A fresh mutable copy is owned by our response; the SDK retains its own
    // immutable copies for its operation lifetime (see documented limitation).
    return HardwareResponse(metadata: metadata, secret: secret.withUnsafeBytes { Data($0) })
}
