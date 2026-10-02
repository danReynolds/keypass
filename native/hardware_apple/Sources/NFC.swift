#if os(iOS)
import Foundation
import CoreNFC
import UIKit
import YubiKit

@MainActor
private final class NFCLease {
    let connection: NFCSmartCardConnection
    private var closing: Task<Void, Never>?
    init(_ connection: NFCSmartCardConnection) { self.connection = connection }
    func close() async {
        if let closing { await closing.value; return }
        let task = Task { await connection.close() }
        closing = task
        await task.value
    }
}

@MainActor
final class NFCHardwareOperation {
    let op: HardwareOperation
    let request: HardwareRequest
    let broker = HardwareBroker.shared
    init(op: HardwareOperation, request: [String: Any]) throws {
        self.op = op; self.request = try HardwareRequest(request)
    }

    private func scan(_ body: (CTAP2.Session, CTAP2.GetInfo.Response) async throws -> HardwareResponse?) async throws -> HardwareResponse? {
        try broker.check(op)
        try broker.event(op, ["event": "presentKey"])
        let connection = try await NFCSmartCardConnection(alertMessage: "Hold your security key near the top of this iPhone. Keep it there until the scan finishes.")
        let lease = NFCLease(connection)
        return try await withTaskCancellationHandler {
            var result: HardwareResponse?
            do {
                try broker.check(op)
                // Standard FIDO AID/CTAP only. No management applet, vendor ID,
                // firmware-version restriction, SCP key or manufacturer allowlist.
                let session = try await CTAP2.Session.makeSession(connection: connection)
                let info = try await session.getInfo()
                try checkHardwareInfo(info, registration: request.operation == "register")
                result = try await body(session, info)
                await lease.close()
                try broker.check(op)
                return result
            } catch {
                result?.clear() // Cancellation while closing must discard a completed PRF too.
                await lease.close()
                throw error
            }
        } onCancel: {
            // Both paths await the same close task before the broker is reusable.
            Task { @MainActor in await lease.close() }
        }
    }

    func run() async throws -> HardwareResponse {
        guard NFCNDEFReaderSession.readingAvailable else { throw HardwareFailure.code("backendUnavailable") }
        guard Bundle.main.bundleURL.pathExtension == "app",
              UIApplication.shared.applicationState == .active,
              Bundle.main.object(forInfoDictionaryKey: "NFCReaderUsageDescription") is String,
              (Bundle.main.object(forInfoDictionaryKey: "com.apple.developer.nfc.readersession.iso7816.select-identifiers") as? [String])?.contains("A0000006472F0001") == true else {
            throw HardwareFailure.code("hostUnavailable")
        }
        // Never enable transport tracing. YubiKit exposes immutable secret
        // objects internally and cannot promise their complete zeroization.
        Logs.configure(logLevel: .critical)
        if request.operation == "discover" {
            return HardwareResponse(metadata: ["devices": [["id": nfcReaderID, "name": "NFC security-key reader"]]])
        }
        let background = NotificationCenter.default.addObserver(forName: UIApplication.didEnterBackgroundNotification,
                                                               object: nil, queue: .main) { [op, broker] _ in broker.cancel(op.id) }
        defer { NotificationCenter.default.removeObserver(background) }
        // First scan discovers verification capabilities. PIN UI cannot be
        // presented behind the system NFC sheet, so close it before requesting PIN.
        var retries: Int?
        if let response = try await scan({ session, info -> HardwareResponse? in
            if info.options.userVerification == true {
                let token: CTAP2.Token?
                if info.options.pinUVAuthToken == true {
                    token = try await session.getPinUVToken(using: .uv,
                        permissions: request.operation == "register" ? .makeCredential : .getAssertion,
                        rpId: request.namespace)
                } else { token = nil } // uv=true is still mandatory on mc/ga.
                return try await performHardwareRequest(request, session: session, token: token)
            }
            guard info.options.clientPin == true else { throw HardwareFailure.code("pinRequired") }
            let state = try await session.getPinRetries()
            guard !state.powerCycleState else { throw HardwareFailure.code("pinTemporarilyBlocked") }
            retries = state.retries
            return nil
        }) { return response }
        guard let retries else { throw HardwareFailure.code("backendFailure") }
        var pin = try await broker.requestPin(op, retries: retries)
        defer { pin.resetBytes(in: 0..<pin.count) }
        guard let pinText = String(data: pin, encoding: .utf8) else { throw HardwareFailure.code("invalidRequest") }
        // This scan is an explicit physical selection by the user. No tag UID is
        // persisted as credential identity; some standards-compliant keys rotate it.
        // The saved credential/signature is independently verified by Dart.
        guard let response = try await scan({ session, info in
            guard info.options.clientPin == true else { throw HardwareFailure.code("pinRequired") }
            let token = try await session.getPinUVToken(using: .pin(pinText),
                permissions: request.operation == "register" ? .makeCredential : .getAssertion,
                rpId: request.namespace)
            try broker.check(op)
            return try await performHardwareRequest(request, session: session, token: token)
        }) else { throw HardwareFailure.code("backendFailure") }
        return response
    }
}
#endif
