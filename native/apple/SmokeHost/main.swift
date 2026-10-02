import Foundation
#if os(macOS)
import AppKit
#else
import UIKit
#endif

// Exercises the real app main-thread/presentation path without opening any
// authentication UI or touching a user's credential provider.
func request(_ json: String) -> UInt64 {
    let data = Data(json.utf8)
    return data.withUnsafeBytes { keypassStart($0.bindMemory(to: UInt8.self).baseAddress, UInt32(data.count)) }
}
func take(_ id: UInt64) -> [String: Any]? {
    var size: UInt32 = 0
    guard let pointer = keypassPoll(id, &size) else { return nil }
    defer { keypassFree(pointer, size) }
    let bytes = UnsafeBufferPointer(start: pointer, count: Int(size))
    let length = (0..<4).reduce(0) { $0 | Int(bytes[4+$1]) << (8*$1) }
    guard size == 12 + length else { return ["error": "unexpectedSecret"] }
    return try? JSONSerialization.jsonObject(with: Data(bytes: pointer.advanced(by: 12), count: length)) as? [String: Any]
}
func probe(_ completion: @escaping (String) -> Void) {
    let cancelled = request("{\"operation\":\"availability\",\"domain\":\"vault.example.com\"}")
    keypassCancel(cancelled)
    guard take(cancelled)?["error"] as? String == "cancelled" else { completion("FAIL cancellation"); return }
    let malformed = request("{")
    guard take(malformed)?["error"] as? String == "invalidRequest" else { completion("FAIL malformed"); return }
    let id = request("{\"operation\":\"availability\",\"domain\":\"vault.example.com\"}")
    let busy = request("{}")
    guard id != 0, busy == 0 else { completion("FAIL busy"); return }
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
        let result = take(id)
        guard let result, result["platform"] as? String == "apple", result["multiple"] as? Bool == true else {
            completion("FAIL presentation host: \(String(describing: result))"); return
        }
        completion("PASS native app presentation, ABI, cancellation, malformed input, busy state. No passkey ceremony attempted.")
    }
}
func save(_ text: String) {
    let directory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    try? text.write(to: directory.appendingPathComponent("keypass-native-smoke.txt"), atomically: true, encoding: .utf8)
}
#if os(macOS)
final class Host: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 640, height: 180), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "Keypass native smoke test"; window.center(); window.makeKeyAndOrderFront(nil); window.makeMain()
        NSApp.activate(ignoringOtherApps: true)
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { probe { result in
            let label = NSTextField(wrappingLabelWithString: result)
            label.frame = NSRect(x: 24, y: 24, width: 590, height: 125)
            self.window.contentView?.addSubview(label)
            // Test-only output in a supplied directory, never a secret.
            if let path = ProcessInfo.processInfo.environment["KEYPASS_SMOKE_RESULT"] {
                try? result.write(toFile: path, atomically: true, encoding: .utf8)
            }
            NSApp.terminate(nil)
        } }
    }
}
let app = NSApplication.shared
let host = Host()
app.delegate = host
app.setActivationPolicy(.regular)
app.run()
#else
final class Host: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        let window = UIWindow(frame: UIScreen.main.bounds)
        let view = UIViewController(); view.view.backgroundColor = .systemBackground
        window.rootViewController = view; self.window = window; window.makeKeyAndVisible()
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            probe { result in
                let label = UILabel(frame: view.view.bounds.insetBy(dx: 24, dy: 80)); label.numberOfLines = 0; label.text = result
                view.view.addSubview(label); save(result)
            }
        }
        return true
    }
}
UIApplicationMain(CommandLine.argc, CommandLine.unsafeArgv, nil, NSStringFromClass(Host.self))
#endif
