import Foundation
import Darwin

enum HardwareFailure: Error {
    case code(String)
}

/// A binary allocation with an explicit wiping lifetime; never serialize secrets.
final class HardwarePacket {
    let pointer: UnsafeMutablePointer<UInt8>
    let length: UInt32
    private var transferred = false
    convenience init(status: UInt32, metadata: [String: Any], secret: Data? = nil) throws {
        guard JSONSerialization.isValidJSONObject(metadata) else { throw HardwareFailure.code("backendFailure") }
        let json = try JSONSerialization.data(withJSONObject: metadata)
        guard json.count <= 65536, secret == nil || secret!.count == 32 else {
            throw HardwareFailure.code("backendFailure")
        }
        self.init(status: status, json: json, secret: secret)
    }
    private init(status: UInt32, json: Data, secret: Data?) {
        length = UInt32(12 + json.count + (secret?.count ?? 0))
        pointer = .allocate(capacity: Int(length))
        for (index, word) in [status, UInt32(json.count), UInt32(secret?.count ?? 0)].enumerated() {
            for byte in 0..<4 { pointer[index * 4 + byte] = UInt8(truncatingIfNeeded: word >> (byte * 8)) }
        }
        json.copyBytes(to: pointer.advanced(by: 12), count: json.count)
        if let secret { secret.copyBytes(to: pointer.advanced(by: 12 + json.count), count: secret.count) }
    }
    static func failure() -> HardwarePacket {
        HardwarePacket(status: 1, json: Data(#"{"error":"backendFailure"}"#.utf8), secret: nil)
    }
    func take() -> UnsafeMutablePointer<UInt8> { transferred = true; return pointer }
    deinit { if !transferred { keypassHardwareFree(pointer, length) } }
}

final class HardwareOperation: @unchecked Sendable {
    let id: UInt64
    var stopReason: String?
    var cancelled: Bool { stopReason != nil }
    var running = true
    var waitingForPin = false
    var pin: Data?
    var packets: [HardwarePacket] = []
    var task: Task<Void, Never>?
    init(_ id: UInt64) { self.id = id }
}

final class HardwareBroker: @unchecked Sendable {
    static let shared = HardwareBroker()
    private let mutex = NSLock()
    private var sequence: UInt64 = 0
    private var active: HardwareOperation?
    func locked<T>(_ body: () throws -> T) rethrows -> T {
        mutex.lock(); defer { mutex.unlock() }; return try body()
    }
    func reserve() -> HardwareOperation? {
        locked {
            guard active == nil, sequence < UInt64.max else { return nil }
            sequence += 1
            let op = HardwareOperation(sequence); active = op; return op
        }
    }
    func check(_ op: HardwareOperation) throws {
        try Task.checkCancellation()
        try locked {
            guard active === op, !op.cancelled else { throw HardwareFailure.code("cancelled") }
        }
    }
    func event(_ op: HardwareOperation, _ value: [String: Any]) throws {
        try check(op)
        let packet = try HardwarePacket(status: 2, metadata: value)
        try locked {
            guard active === op, !op.cancelled, op.running, op.packets.count < 4 else {
                throw HardwareFailure.code("cancelled")
            }
            op.packets.append(packet)
        }
    }
    func finish(_ op: HardwareOperation, metadata: [String: Any]) {
        var response = HardwareResponse(metadata: metadata, secret: nil)
        finish(op, response: &response)
    }
    /// Consume and clear the worker-owned secret before making a packet visible.
    func finish(_ op: HardwareOperation, response: inout HardwareResponse) {
        let packet = (try? HardwarePacket(status: response.metadata["error"] == nil ? 0 : 1,
                                         metadata: response.metadata, secret: response.secret)) ?? HardwarePacket.failure()
        response.clear()
        locked {
            guard active === op, op.running else { return }
            op.waitingForPin = false
            if op.pin != nil { op.pin!.resetBytes(in: 0..<op.pin!.count); op.pin = nil }
            op.packets.removeAll()
            if let reason = op.stopReason {
                op.packets.append((try? HardwarePacket(status: 1, metadata: ["error": reason])) ?? HardwarePacket.failure())
            } else {
                op.packets.append(packet)
            }
            op.running = false
            op.task = nil
        }
    }
    func poll(_ id: UInt64, _ size: UnsafeMutablePointer<UInt32>?) -> UnsafeMutablePointer<UInt8>? {
        locked {
            guard let size else { return nil }; size.pointee = 0
            guard let op = active, op.id == id, !op.packets.isEmpty else { return nil }
            let packet = op.packets.removeFirst()
            if !op.running && op.packets.isEmpty { active = nil }
            size.pointee = packet.length
            return packet.take()
        }
    }
    func setTask(_ op: HardwareOperation, _ task: Task<Void, Never>) {
        locked { if active === op && op.running { op.task = task; if op.cancelled { task.cancel() } } else { task.cancel() } }
    }
    func cancel(_ id: UInt64, reason: String = "cancelled") {
        let task = locked { () -> Task<Void, Never>? in
            guard let op = active, op.id == id, op.running else { return nil }
            op.stopReason = op.stopReason ?? reason; return op.task
        }
        task?.cancel()
    }
    func submit(_ id: UInt64, _ pointer: UnsafePointer<UInt8>?, _ size: UInt32) -> UInt32 {
        guard let pointer, size >= 4, size <= 63 else { return 0 }
        let buffer = UnsafeBufferPointer(start: pointer, count: Int(size))
        guard !buffer.contains(0) else { return 0 }
        return locked {
            guard let op = active, op.id == id, op.waitingForPin, op.pin == nil, !op.cancelled else { return 0 }
            op.pin = Data(buffer); return 1
        }
    }
    func requestPin(_ op: HardwareOperation, retries: Int) async throws -> Data {
        guard retries > 0 else { throw HardwareFailure.code("pinBlocked") }
        locked { op.waitingForPin = true }
        defer { locked { op.waitingForPin = false } }
        try event(op, ["event": "pin", "attemptsRemaining": retries])
        while true {
            try check(op)
            if let pin = locked({ () -> Data? in
                guard let pin = op.pin else { return nil }
                op.pin = nil; return pin
            }) { return pin }
            try await Task.sleep(nanoseconds: 25_000_000)
        }
    }
}

@_cdecl("keypass_hardware_abi_version") public func keypassHardwareVersion() -> UInt32 { 1 }
@_cdecl("keypass_hardware_start") public func keypassHardwareStart(_ input: UnsafePointer<UInt8>?, _ size: UInt32) -> UInt64 {
    guard let input, size > 0, size <= 65536 else { return 0 }
    let broker = HardwareBroker.shared
    guard let op = broker.reserve() else { return 0 }
    guard let request = try? JSONSerialization.jsonObject(with: Data(bytes: input, count: Int(size))) as? [String: Any] else {
        broker.finish(op, metadata: ["error": "invalidRequest"]); return op.id
    }
    let task = Task { @MainActor in
        let timeout = Task {
            try? await Task.sleep(nanoseconds: 120_000_000_000)
            if !Task.isCancelled { broker.cancel(op.id, reason: "timeout") }
        }
        defer { timeout.cancel() }
        do {
#if os(iOS)
            var response = try await NFCHardwareOperation(op: op, request: request).run()
            timeout.cancel()
            await timeout.value
            broker.finish(op, response: &response)
#else
            timeout.cancel()
            await timeout.value
            broker.finish(op, metadata: ["error": "backendUnavailable"])
#endif
        } catch {
            timeout.cancel()
            await timeout.value
            broker.finish(op, metadata: ["error": hardwareErrorCode(error)])
        }
    }
    broker.setTask(op, task)
    return op.id
}
@_cdecl("keypass_hardware_poll") public func keypassHardwarePoll(_ id: UInt64, _ size: UnsafeMutablePointer<UInt32>?) -> UnsafeMutablePointer<UInt8>? {
    HardwareBroker.shared.poll(id, size)
}
@_cdecl("keypass_hardware_pin") public func keypassHardwarePin(_ id: UInt64, _ pin: UnsafePointer<UInt8>?, _ size: UInt32) -> UInt32 {
    HardwareBroker.shared.submit(id, pin, size)
}
@_cdecl("keypass_hardware_cancel") public func keypassHardwareCancel(_ id: UInt64) { HardwareBroker.shared.cancel(id) }
@_cdecl("keypass_hardware_free") public func keypassHardwareFree(_ data: UnsafeMutablePointer<UInt8>?, _ size: UInt32) {
    guard let data else { return }; _ = memset_s(data, Int(size), 0, Int(size)); data.deallocate()
}
