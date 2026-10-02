import XCTest
@testable import KeypassHardwareApple

final class BridgeTests: XCTestCase {
    func testHardwareRequestRejectsInvalidDataBeforeScan() throws {
        XCTAssertThrowsError(try HardwareRequest(["operation": "evaluate", "device": nfcReaderID]))
        XCTAssertThrowsError(try HardwareRequest(["operation": "reset"]))
        let request = try HardwareRequest(["operation": "discover"])
        XCTAssertEqual(request.operation, "discover")
    }
    func testBinaryFrameHasSeparateSecretAndOwnership() throws {
        let packet = try HardwarePacket(status: 0, metadata: ["ok": true], secret: Data(repeating: 7, count: 32))
        let p = packet.take()
        defer { keypassHardwareFree(p, packet.length) }
        XCTAssertEqual(p[0], 0)
        XCTAssertEqual(p[8], 32)
        let jsonLength = Int(p[4]) | Int(p[5]) << 8
        XCTAssertEqual(Int(packet.length), 12 + jsonLength + 32)
        XCTAssertEqual(p[12 + jsonLength], 7)
    }
    func testSuccessConsumesWorkerSecretBeforePacketCanBePolled() throws {
        let broker = HardwareBroker()
        let op = try XCTUnwrap(broker.reserve())
        var response = HardwareResponse(metadata: ["ok": true], secret: Data(repeating: 7, count: 32))
        broker.finish(op, response: &response)
        XCTAssertNil(response.secret)
        XCTAssertNil(op.task)
        XCTAssertFalse(op.running)
        var size: UInt32 = 0
        let frame = try XCTUnwrap(broker.poll(op.id, &size))
        defer { keypassHardwareFree(frame, size) }
        XCTAssertEqual(frame[0], 0)
        XCTAssertEqual(frame[8], 32)
        XCTAssertEqual(frame[Int(size) - 1], 7)
        XCTAssertNotNil(broker.reserve())
    }
    func testCancellationDiscardsLateSecretAndBlocksReuseUntilDrained() throws {
        let broker = HardwareBroker()
        let op = try XCTUnwrap(broker.reserve())
        XCTAssertNil(broker.reserve())
        broker.cancel(op.id)
        var response = HardwareResponse(metadata: ["ok": true], secret: Data(repeating: 7, count: 32))
        broker.finish(op, response: &response)
        XCTAssertNil(response.secret)
        XCTAssertNil(broker.reserve())
        var size: UInt32 = 0
        let frame = try XCTUnwrap(broker.poll(op.id, &size))
        defer { keypassHardwareFree(frame, size) }
        XCTAssertEqual(frame[0], 1)
        XCTAssertEqual(frame[8], 0)
        XCTAssertNotNil(broker.reserve())
    }
}
