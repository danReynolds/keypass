import AuthenticationServices
import Foundation
import Darwin
import CryptoKit
#if os(macOS)
import AppKit
#else
import UIKit
#endif

// The C ABI is callable on Dart worker threads. Only packet ownership and IDs
// use this lock; AuthenticationServices and presentation state stay on main.
private let lock = NSLock()
private var nextID: UInt64 = 0
private var pending: Set<UInt64> = []
private var packets: [UInt64: (UnsafeMutablePointer<UInt8>, UInt32)] = [:]
private var providerBusy = false
private var controllers: [UInt64: Ceremony] = [:] // main thread only
#if !os(macOS)
private var presentationWaiters: [UInt64: IOSPresentationWait] = [:] // main thread only
#endif

private func locked<T>(_ body: () -> T) -> T {
    lock.lock(); defer { lock.unlock() }; return body()
}
private func finish(_ id: UInt64, _ metadata: [String: Any], secret: UnsafeRawBufferPointer? = nil) {
    let json = (try? JSONSerialization.data(withJSONObject: metadata)) ?? Data("{\"error\":\"backendFailure\"}".utf8)
    guard json.count <= 65536, secret == nil || secret!.count == 32 else {
        finish(id, ["error": "backendFailure"]); return
    }
    let count = 12 + json.count + (secret?.count ?? 0)
    let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
    func word(_ value: UInt32, _ offset: Int) {
        for i in 0..<4 { buffer[offset + i] = UInt8(truncatingIfNeeded: value >> (i * 8)) }
    }
    word(metadata["error"] == nil ? 0 : 1, 0)
    word(UInt32(json.count), 4); word(UInt32(secret?.count ?? 0), 8)
    json.copyBytes(to: buffer.advanced(by: 12), count: json.count)
    if let secret { buffer.advanced(by: 12 + json.count).update(from: secret.bindMemory(to: UInt8.self).baseAddress!, count: secret.count) }
    let accepted = locked { () -> Bool in
        guard pending.contains(id), packets[id] == nil else { return false }
        packets[id] = (buffer, UInt32(count)); return true
    }
    if !accepted { keypassFree(buffer, UInt32(count)) }
}
private func fail(_ id: UInt64, _ code: String) { finish(id, ["error": code]) }
private func b64(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}
private func bytes(_ value: Any?) throws -> Data {
    guard let text = value as? String, !text.isEmpty, text.count <= 8192,
          text.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil else { throw Failure.invalid }
    var standard = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    standard += String(repeating: "=", count: (4 - standard.count % 4) % 4)
    guard let data = Data(base64Encoded: standard), b64(data) == text else { throw Failure.invalid }
    return data
}
private enum Failure: Error { case invalid }

@_cdecl("keypass_abi_version") public func keypassVersion() -> UInt32 { 1 }
@_cdecl("keypass_start") public func keypassStart(_ input: UnsafePointer<UInt8>?, _ length: UInt32) -> UInt64 {
    let id = locked { () -> UInt64 in
        guard pending.isEmpty, !providerBusy, nextID < UInt64.max else { return 0 }
        nextID += 1; pending.insert(nextID); return nextID
    }
    guard id != 0 else { return 0 }
    guard let input, length > 0, length <= 262144,
          let request = try? JSONSerialization.jsonObject(with: Data(bytes: input, count: Int(length))) as? [String: Any] else {
        fail(id, "invalidRequest"); return id
    }
    guard #available(macOS 15.0, iOS 18.0, *) else { fail(id, "backendUnavailable"); return id }
    // Unsigned CLI processes cannot acquire app-domain authorization by linking
    // this library. Standalone CLIs use the planned physical-key backend.
    guard Bundle.main.bundleURL.pathExtension == "app" else { fail(id, "hostUnavailable"); return id }
    DispatchQueue.main.async {
        guard locked({ pending.contains(id) && packets[id] == nil }) else { return }
        withPresentationWindow(id) { window in
            // Cancellation may have completed the packet while the scene resumed.
            guard locked({ pending.contains(id) && packets[id] == nil }) else { return }
            guard let window else { fail(id, "hostUnavailable"); return }
            if request["operation"] as? String == "availability" {
                guard let domain = request["domain"] as? String else { fail(id, "invalidRequest"); return }
                finish(id, ["platform": "apple", "origin": "https://\(domain)", "multiple": true]); return
            }
            do {
                let ceremony = try Ceremony(id: id, request: request, window: window)
                controllers[id] = ceremony
                locked { providerBusy = true }
                ceremony.begin()
            } catch { fail(id, "invalidRequest") }
        }
    }
    return id
}
@_cdecl("keypass_poll") public func keypassPoll(_ id: UInt64, _ length: UnsafeMutablePointer<UInt32>?) -> UnsafeMutablePointer<UInt8>? {
    locked {
        guard let length, let packet = packets[id] else { return nil }
        // Success waits for the delegate/controller teardown. Cancellation may
        // return early, but providerBusy fences late framework callbacks and UI.
        guard packet.0[0] != 0 || !providerBusy else { return nil }
        packets.removeValue(forKey: id)
        pending.remove(id); length.pointee = packet.1; return packet.0
    }
}
@_cdecl("keypass_cancel") public func keypassCancel(_ id: UInt64) {
    // Complete without waiting for a framework callback; that callback retains
    // its controller and is ignored after this response has been consumed.
    fail(id, "cancelled")
    DispatchQueue.main.async {
#if !os(macOS)
        presentationWaiters.removeValue(forKey: id)?.cancel()
#endif
        controllers[id]?.controller.cancel()
    }
}
@_cdecl("keypass_free") public func keypassFree(_ buffer: UnsafeMutablePointer<UInt8>?, _ length: UInt32) {
    guard let buffer else { return }
    _ = memset_s(buffer, Int(length), 0, Int(length)); buffer.deallocate()
}

// A provider callback may arrive before its sheet has dismissed and the host
// scene becomes active again. Keep the original window; never move a queued
// request to a different scene, or resurrect it after cancellation/timeout.
enum PresentationState<Host: AnyObject> {
    case active(Host)
    case transitioning(Host)
    case unavailable
}

final class PresentationGate<Host: AnyObject> {
    private var owner: Host?
    private var completion: ((Host?) -> Void)?

    init(completion: @escaping (Host?) -> Void) { self.completion = completion }

    func update(_ state: PresentationState<Host>) {
        guard completion != nil else { return }
        let host: Host
        let active: Bool
        switch state {
        case .active(let value): host = value; active = true
        case .transitioning(let value): host = value; active = false
        case .unavailable: finish(nil); return
        }
        if let owner, owner !== host { finish(nil); return }
        owner = host
        if active { finish(host) }
    }

    func expire() { finish(nil) }
    func cancel() { completion = nil; owner = nil }

    private func finish(_ host: Host?) {
        let callback = completion
        completion = nil; owner = nil
        callback?(host)
    }
}

private func withPresentationWindow(_ id: UInt64, completion: @escaping (ASPresentationAnchor?) -> Void) {
#if os(macOS)
    if let active = NSApplication.shared.keyWindow ?? NSApplication.shared.mainWindow {
        completion(active); return
    }
    let windows = NSApplication.shared.windows.filter { $0.isVisible && $0.canBecomeKey && !($0 is NSPanel) }
    completion(windows.count == 1 ? windows[0] : nil)
#else
    let waiter = IOSPresentationWait { window in
        presentationWaiters.removeValue(forKey: id)
        completion(window)
    }
    presentationWaiters[id] = waiter
    waiter.start()
#endif
}

#if !os(macOS)
private func iosPresentationState() -> PresentationState<UIWindow> {
    let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        .filter { $0.activationState == .foregroundActive || $0.activationState == .foregroundInactive }
    // An inactive scene is a candidate to wait for, not permission to present.
    // Exclude background scenes and refuse ambiguous foreground ownership.
    guard scenes.count == 1 else { return .unavailable }
    let scene = scenes[0]
    let visible = scene.windows.filter { !$0.isHidden && $0.alpha > 0 && $0.windowLevel == .normal }
    let keys = visible.filter { $0.isKeyWindow }
    guard keys.count <= 1 else { return .unavailable }
    guard let window = keys.first ?? (visible.count == 1 ? visible[0] : nil) else { return .unavailable }
    if scene.activationState == .foregroundActive && window.isKeyWindow { return .active(window) }
    return .transitioning(window)
}

private final class IOSPresentationWait {
    private var observers: [NSObjectProtocol] = []
    private var deadline: DispatchWorkItem?
    private var completion: ((UIWindow?) -> Void)?
    private lazy var gate = PresentationGate<UIWindow> { [weak self] window in
        guard let self else { return }
        self.stopObserving()
        let callback = self.completion
        self.completion = nil
        callback?(window)
    }

    init(completion: @escaping (UIWindow?) -> Void) { self.completion = completion }

    func start() {
        let names: [Notification.Name] = [
            UIScene.didActivateNotification, UIScene.willDeactivateNotification,
            UIScene.didEnterBackgroundNotification, UIScene.didDisconnectNotification,
            UIWindow.didBecomeKeyNotification, UIWindow.didResignKeyNotification,
            UIWindow.didBecomeVisibleNotification, UIWindow.didBecomeHiddenNotification,
        ]
        for name in names {
            observers.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                // Observe completed lifecycle state, after UIKit updates it.
                DispatchQueue.main.async { self?.refresh() }
            })
        }
        let timeout = DispatchWorkItem { [weak self] in self?.gate.expire() }
        deadline = timeout
        DispatchQueue.main.asyncAfter(deadline: .now() + 3, execute: timeout)
        refresh()
    }

    private func refresh() { gate.update(iosPresentationState()) }

    func cancel() {
        gate.cancel()
        completion = nil
        stopObserving()
    }

    private func stopObserving() {
        deadline?.cancel(); deadline = nil
        observers.forEach { NotificationCenter.default.removeObserver($0) }
        observers.removeAll()
    }

    deinit { stopObserving() }
}
#endif

@available(macOS 15.0, iOS 18.0, *)
private final class Ceremony: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    let id: UInt64
    let window: ASPresentationAnchor
    let controller: ASAuthorizationController
    private var deadline: DispatchWorkItem?
    private var ended = false

    init(id: UInt64, request: [String: Any], window: ASPresentationAnchor) throws {
        self.id = id; self.window = window
        guard let options = request["publicKey"] as? [String: Any] else { throw Failure.invalid }
        let challenge = try bytes(options["challenge"])
        guard challenge.count == 32 else { throw Failure.invalid }
        let native: ASAuthorizationRequest
        if request["operation"] as? String == "register" {
            guard let rp = options["rp"] as? [String: Any], let domain = rp["id"] as? String,
                  let user = options["user"] as? [String: Any], let label = user["name"] as? String else { throw Failure.invalid }
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: domain)
            let registration = provider.createCredentialRegistrationRequest(challenge: challenge, name: label, userID: try bytes(user["id"]))
            registration.userVerificationPreference = .required
            registration.attestationPreference = .none
            registration.prf = .checkForSupport
            native = registration
        } else if request["operation"] as? String == "evaluate" {
            guard let domain = options["rpId"] as? String,
                  let allowed = options["allowCredentials"] as? [[String: Any]], !allowed.isEmpty, allowed.count <= 64,
                  let extensions = options["extensions"] as? [String: Any], let prf = extensions["prf"] as? [String: Any],
                  let inputs = prf["evalByCredential"] as? [String: [String: Any]] else { throw Failure.invalid }
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: domain)
            let assertion = provider.createCredentialAssertionRequest(challenge: challenge)
            assertion.userVerificationPreference = .required
            var salts: [Data: ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues] = [:]
            assertion.allowedCredentials = try allowed.map { item in
                let credential = try bytes(item["id"])
                guard let text = item["id"] as? String, let value = inputs[text] else { throw Failure.invalid }
                salts[credential] = .init(saltInput1: try bytes(value["first"]))
                return ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: credential)
            }
            assertion.prf = .perCredentialInputValues(salts)
            native = assertion
        } else { throw Failure.invalid }
        controller = ASAuthorizationController(authorizationRequests: [native])
        super.init()
        controller.delegate = self; controller.presentationContextProvider = self
    }
    func begin() {
        let timeout = DispatchWorkItem { [weak self] in
            guard let self, !self.ended else { return }
            fail(self.id, "timeout"); self.controller.cancel()
        }
        deadline = timeout
        DispatchQueue.main.asyncAfter(deadline: .now() + 120, execute: timeout)
        controller.performRequests()
    }
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor { window }
    private func end() {
        guard !ended else { return }; ended = true
        deadline?.cancel(); deadline = nil
        controller.delegate = nil
        controller.presentationContextProvider = nil
        controllers.removeValue(forKey: id)
        locked { providerBusy = false }
    }
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        defer { end() }
        if let registration = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration,
           let attestation = registration.rawAttestationObject {
            finish(id, ["credentialId": b64(registration.credentialID),
                        "clientDataJSON": b64(registration.rawClientDataJSON),
                        "attestationObject": b64(attestation), "prfEnabled": registration.prf?.isSupported == true])
        } else if let assertion = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
            guard let secret = assertion.prf?.first, secret.bitCount == 256 else { fail(id, "prfUnavailable"); return }
            var metadata: [String: Any] = ["credentialId": b64(assertion.credentialID),
                "clientDataJSON": b64(assertion.rawClientDataJSON), "authenticatorData": b64(assertion.rawAuthenticatorData),
                "signature": b64(assertion.signature)]
            if !assertion.userID.isEmpty { metadata["userHandle"] = b64(assertion.userID) }
            secret.withUnsafeBytes { finish(id, metadata, secret: $0) }
        } else { fail(id, "verificationFailed") }
    }
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        defer { end() }
        let e = error as NSError
        let code = e.domain == ASAuthorizationError.errorDomain && e.code == ASAuthorizationError.canceled.rawValue
            ? "cancelled" : "backendFailure"
        fail(id, code)
    }
}
