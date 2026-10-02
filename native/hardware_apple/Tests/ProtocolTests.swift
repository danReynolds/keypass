import Foundation
import CryptoKit
import XCTest
@testable import YubiKit
@testable import KeypassHardwareApple

final class ProtocolTests: XCTestCase {
    private func info(prf: Bool = true, pin: Bool = true, protection: Bool = true) -> CBOR.Value {
        var extensions: [CBOR.Value] = prf ? [.textString("hmac-secret")] : []
        if protection { extensions.append(.textString("credProtect")) }
        return .map([
            .int(1): .array([.textString("FIDO_2_0")]),
            .int(2): .array(extensions),
            .int(3): .byteString(Data(repeating: 0xa5, count: 16)), // Arbitrary vendor.
            .int(4): .map([.textString("rk"): .boolean(true),
                          .textString("up"): .boolean(true),
                          .textString("clientPin"): .boolean(pin)])
        ])
    }
    func testCapabilityChecksIgnoreVendorAndRejectMissingProtection() throws {
        try checkHardwareInfo(XCTUnwrap(CTAP2.GetInfo.Response(cbor: info())), registration: true)
        for (value, code) in [(info(prf: false), "prfUnavailable"),
                              (info(pin: false), "pinRequired"),
                              (info(protection: false), "verificationUnavailable")] {
            XCTAssertThrowsError(try checkHardwareInfo(XCTUnwrap(CTAP2.GetInfo.Response(cbor: value)), registration: true)) {
                XCTAssertEqual(hardwareErrorCode($0), code)
            }
        }
    }
    func testNFCSessionSelectsOnlyStandardFIDOApplication() async throws {
        let connection = ScriptedCard([
            Data("U2F_V2".utf8) + Data([0x90, 0]),
            Data([0]) + info().encode() + Data([0x90, 0])
        ])
        let session = try await CTAP2.Session.makeSession(connection: connection)
        let result = try await session.getInfo()
        try checkHardwareInfo(result, registration: true)
        let sent = await connection.sent
        XCTAssertEqual(sent.count, 2)
        // Standard ISO SELECT for A0000006472F0001; no vendor-management applet.
        XCTAssertEqual(Data(sent[0].prefix(13)), Data([0, 0xa4, 4, 0, 8, 0xa0, 0, 0, 6, 0x47, 0x2f, 0, 1]))
        XCTAssertEqual(Data(sent[1].prefix(4)), Data([0x80, 0x10, 0x80, 0]))
    }
    func testPackedSelfAttestationRequiresCorrectKeyDataAndChallenge() throws {
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey.x963Representation
        let cose: CBOR.Value = .map([
            .int(1): .int(2), .int(3): .int(-7), .int(-1): .int(1),
            .int(-2): .byteString(publicKey.subdata(in: 1..<33)),
            .int(-3): .byteString(publicKey.subdata(in: 33..<65))
        ])
        let hash = Data(repeating: 42, count: 32)
        var auth = Data(SHA256.hash(data: Data("dev.keypass.test".utf8)))
        auth += Data([0xc5, 0, 0, 0, 1]) + Data(repeating: 0xa5, count: 16)
        auth += Data([0, 16]) + Data(repeating: 3, count: 16) + cose.encode()
        auth += CBOR.Value.map([.textString("hmac-secret"): .boolean(true),
                                .textString("credProtect"): .int(3)]).encode()
        let signature = try privateKey.signature(for: auth + hash).derRepresentation
        func response(_ bytes: Data, _ format: String = "packed") throws -> CTAP2.MakeCredential.Response {
            try XCTUnwrap(CTAP2.MakeCredential.Response(cbor: .map([
                .int(1): .textString(format), .int(2): .byteString(bytes),
                .int(3): .map([.textString("alg"): .int(-7), .textString("sig"): .byteString(signature)])
            ])))
        }
        try verifyHardwarePacked(response(auth), hash: hash)
        XCTAssertThrowsError(try verifyHardwarePacked(response(auth), hash: Data(repeating: 1, count: 32)))
        var tampered = auth
        tampered[36] ^= 1
        XCTAssertThrowsError(try verifyHardwarePacked(response(tampered), hash: hash))
        XCTAssertThrowsError(try verifyHardwarePacked(response(auth, "none"), hash: hash))
    }
    func testSaltIsPassedThroughWithoutAnotherNormalization() throws {
        let salt = Data(repeating: 17, count: 32)
        let request = try HardwareRequest([
            "operation": "evaluate", "namespace": "dev.keypass.test", "device": nfcReaderID,
            "clientDataHash": hardwareBase64(Data(repeating: 1, count: 32)),
            "credentialId": hardwareBase64(Data([2])),
            "hmacSalt": hardwareBase64(salt)
        ])
        XCTAssertEqual(request.salt, salt)
    }
    func testTimeoutWinsAndMalformedOutputFailsClosed() throws {
        for malformed in [false, true] {
            let broker = HardwareBroker()
            let op = try XCTUnwrap(broker.reserve())
            if !malformed {
                broker.cancel(op.id, reason: "timeout")
                broker.cancel(op.id) // Cleanup must not overwrite the cause.
            }
            var response = HardwareResponse(metadata: malformed ? ["invalid": Date()] : ["ok": true],
                                            secret: Data(repeating: 9, count: 32))
            broker.finish(op, response: &response)
            XCTAssertNil(response.secret)
            var size: UInt32 = 0
            let frame = try XCTUnwrap(broker.poll(op.id, &size))
            defer { keypassHardwareFree(frame, size) }
            XCTAssertEqual(frame[0], 1)
            XCTAssertEqual(frame[8], 0)
            let json = try JSONSerialization.jsonObject(with: Data(bytes: frame + 12, count: Int(size) - 12)) as? [String: String]
            XCTAssertEqual(json?["error"], malformed ? "backendFailure" : "timeout")
            XCTAssertNotNil(broker.reserve())
        }
    }
}
private actor ScriptedCard: SmartCardConnection {
    private var responses: [Data]
    private(set) var sent: [Data] = []
    init(_ responses: [Data]) { self.responses = responses }
    init() async throws(SmartCardConnectionError) { throw .unsupported }
    static func makeConnection() async throws(SmartCardConnectionError) -> ScriptedCard { throw .unsupported }
    func send(data: Data) async throws(SmartCardConnectionError) -> Data {
        sent.append(data)
        guard !responses.isEmpty else { throw .malformedData() }
        return responses.removeFirst()
    }
    func close(error: Error?) async {}
    func waitUntilClosed() async -> Error? { nil }
}
