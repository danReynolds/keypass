import AppKit
import Foundation
import Darwin
import CryptoKit

// Demo-only AppKit host. A bundled AOT Dart worker owns Keypass's orchestration,
// WebAuthn verification and encrypted marker; private inherited pipes carry the
// native ABI evidence and binary secret. This is not a production IPC backend.
final class DemoHost: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    var status: NSTextField!
    var details: NSTextField!
    var check: NSButton!
    var enroll: NSButton!
    var unlock: NSButton!
    var cancel: NSButton!
    var worker: Process?
    var input: FileHandle?
    var output: FileHandle?
    var reader = Data()
    var polls: [Int: (UInt64, Timer)] = [:]
    var configured = false
    var saved = false
    var busy = false
    var lastStatus = "Starting Dart…"
    var statePath = ""
    let domain = Bundle.main.object(forInfoDictionaryKey: "KeypassDomain") as? String ?? ""

    func applicationDidFinishLaunching(_ notification: Notification) {
        signal(SIGPIPE, SIG_IGN)
        makeWindow()
        do { try launchWorker() }
        catch { update("Could not start the bundled Dart SDK worker.") }
    }
    func makeWindow() {
        window = NSWindow(contentRect:NSRect(x:0,y:0,width:720,height:460), styleMask:[.titled,.closable,.miniaturizable], backing:.buffered, defer:false)
        window.title = "Keypass Demo"; window.center()
        let stack = NSStackView(); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 18
        stack.translatesAutoresizingMaskIntoConstraints = false
        let content = window.contentView!; content.addSubview(stack)
        NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo:content.leadingAnchor,constant:28),
            stack.trailingAnchor.constraint(equalTo:content.trailingAnchor,constant:-28), stack.topAnchor.constraint(equalTo:content.topAnchor,constant:28)])
        let title = NSTextField(labelWithString:"Passkeys that unlock encrypted data")
        title.font = .systemFont(ofSize:24,weight:.semibold); stack.addArrangedSubview(title)
        let intro = NSTextField(wrappingLabelWithString:"Create a test passkey, then quit and reopen this app. Unlock checks whether it can decrypt the saved test marker. Your passkey secret is never displayed or saved.")
        intro.font = .systemFont(ofSize:14); stack.addArrangedSubview(intro)
        let identity = NSTextField(labelWithString:domain.isEmpty ? "RP domain: not configured" : "RP domain: \(domain)")
        identity.font = .monospacedSystemFont(ofSize:13,weight:.regular); stack.addArrangedSubview(identity)
        let buttons = NSStackView(); buttons.orientation = .horizontal; buttons.spacing = 10
        check = button("Check connection",#selector(checkHost))
        enroll = button("Create test passkey",#selector(createPasskey))
        unlock = button("Unlock saved test",#selector(unlockTest))
        cancel = button("Cancel",#selector(cancelOperation))
        [check,enroll,unlock,cancel].forEach { buttons.addArrangedSubview($0!) }; stack.addArrangedSubview(buttons)
        status = NSTextField(wrappingLabelWithString:lastStatus); status.font = .systemFont(ofSize:15,weight:.medium)
        status.setContentCompressionResistancePriority(.required,for:.vertical)
        stack.addArrangedSubview(status)
        details = NSTextField(wrappingLabelWithString:domain.isEmpty
            ? "Native passkey creation needs a signed app associated with an HTTPS domain you control. Check connection can run now without opening a passkey prompt."
            : "Enrollment opens the platform's create dialog followed by two verification prompts. Follow those prompts, then unlock after restarting the app.")
        details.textColor = .secondaryLabelColor; details.font = .systemFont(ofSize:12)
        stack.addArrangedSubview(details)
        let footer = NSTextField(labelWithString:"Development demo · macOS native provider + Dart Keypass SDK")
        footer.textColor = .secondaryLabelColor; footer.font = .systemFont(ofSize:11); stack.addArrangedSubview(footer)
        window.makeKeyAndOrderFront(nil); window.makeMain(); NSApp.activate(ignoringOtherApps:true)
        syncButtons()
    }
    func button(_ text: String,_ action: Selector) -> NSButton {
        let result = NSButton(title:text,target:self,action:action); result.bezelStyle = .rounded; return result
    }
    func syncButtons() {
        check.isEnabled = worker?.isRunning == true && !busy
        enroll.isEnabled = configured && !saved && !busy
        unlock.isEnabled = configured && saved && !busy
        cancel.isEnabled = busy
    }
    func update(_ text: String) { lastStatus = text; status.stringValue = text; syncButtons(); receipt() }
    func receipt() {
        let value: [String:Any] = ["status":lastStatus,"busy":busy,"configured":configured,"saved":saved,"domain":domain,"pid":ProcessInfo.processInfo.processIdentifier]
        if let path = ProcessInfo.processInfo.environment["KEYPASS_DEMO_RECEIPT"],
           let data = try? JSONSerialization.data(withJSONObject:value,options:[.sortedKeys]) {
            try? data.write(to:URL(fileURLWithPath:path),options:.atomic)
        }
    }
    func launchWorker() throws {
        let directory = FileManager.default.urls(for:.applicationSupportDirectory,in:.userDomainMask)[0]
            .appendingPathComponent("Keypass Demo",isDirectory:true)
            .appendingPathComponent(domain.isEmpty ? "unconfigured" : domain,isDirectory:true)
        try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        statePath = directory.appendingPathComponent("encrypted-test.json").path
        let process = Process(); process.executableURL = Bundle.main.url(forResource:"keypass-demo-worker",withExtension:nil)!
        process.arguments = [domain,statePath]
        let toWorker = Pipe(), fromWorker = Pipe()
        process.standardInput = toWorker; process.standardOutput = fromWorker; process.standardError = FileHandle.nullDevice
        input = toWorker.fileHandleForWriting; output = fromWorker.fileHandleForReading; worker = process
        output!.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            DispatchQueue.main.async {
                guard let self else { return }
                if data.isEmpty { handle.readabilityHandler = nil; return }
                self.reader.append(data); self.readFrames()
            }
        }
        process.terminationHandler = { [weak self] process in DispatchQueue.main.async {
            guard let self else { return }
            self.busy = false; self.update("Dart worker stopped (exit \(process.terminationStatus)). Reopen the demo to retry.")
        } }
        try process.run(); syncButtons()
    }
    func word(_ data: Data,_ offset: Int) -> Int {
        (0..<4).reduce(0) { $0 | Int(data[data.startIndex + offset + $1]) << (8*$1) }
    }
    func readFrames() {
        do {
            while reader.count >= 8 {
                let length = word(reader,0), secretLength = word(reader,4)
                // The worker never sends secrets to the host.
                guard length > 0, length <= 262144, secretLength == 0 else { throw DemoError.protocolFailure }
                guard reader.count >= 8 + length else { return }
                let publicData = reader.subdata(in:reader.startIndex+8..<reader.startIndex+8+length)
                reader.removeFirst(8+length)
                guard let message = try JSONSerialization.jsonObject(with:publicData) as? [String:Any] else { throw DemoError.protocolFailure }
                receive(message)
            }
        } catch { update("The demo's Dart connection failed."); worker?.terminate() }
    }
    func receive(_ message:[String:Any]) {
        switch message["kind"] as? String {
        case "ready":
            configured = message["configured"] as? Bool ?? false; saved = message["saved"] as? Bool ?? false
            update(saved ? "A saved encrypted test is available. Unlock it to check recovery." : "Dart SDK ready. Check the native connection to begin.")
            if CommandLine.arguments.contains("--check") { checkHost() }
        case "status":
            busy = message["busy"] as? Bool ?? false; saved = message["saved"] as? Bool ?? false
            update(message["message"] as? String ?? "Operation stopped.")
        case "idle":
            busy = false; saved = message["saved"] as? Bool ?? false; syncButtons(); receipt()
        case "nativeRequest":
            guard let id = message["id"] as? Int, let request = message["request"] as? [String:Any],
                  let data = try? JSONSerialization.data(withJSONObject:request) else { return }
            let nativeID = data.withUnsafeBytes { keypassStart($0.bindMemory(to:UInt8.self).baseAddress,UInt32(data.count)) }
            if nativeID == 0 {
                send(["kind":"nativeResponse","id":id,"status":1,"metadata":["error":"busy"]]); return
            }
            let timer = Timer(timeInterval:0.02,repeats:true) { [weak self] _ in self?.poll(id,nativeID) }
            polls[id] = (nativeID,timer); RunLoop.main.add(timer,forMode:.common)
        case "nativeCancel":
            if let id = message["id"] as? Int, let pending = polls[id] { keypassCancel(pending.0) }
        default: break
        }
    }
    func poll(_ id:Int,_ nativeID:UInt64) {
        var length:UInt32 = 0
        guard let pointer = keypassPoll(nativeID,&length) else { return }
        defer { keypassFree(pointer,length) }
        polls.removeValue(forKey:id)?.1.invalidate()
        guard length >= 12, length <= 65580 else { update("Native response was invalid."); return }
        func header(_ offset:Int) -> Int { (0..<4).reduce(0) { $0 | Int(pointer[offset+$1]) << (8*$1) } }
        let jsonLength = header(4), secretLength = header(8)
        guard jsonLength <= 65536, [0,32].contains(secretLength), Int(length) == 12+jsonLength+secretLength,
              let metadata = try? JSONSerialization.jsonObject(with:Data(bytes:pointer.advanced(by:12),count:jsonLength)) else {
            send(["kind":"nativeResponse","id":id,"status":1,"metadata":["error":"backendFailure"]]); return
        }
        send(["kind":"nativeResponse","id":id,"status":header(0),"metadata":metadata],
            secret:UnsafeRawBufferPointer(start:pointer.advanced(by:12+jsonLength),count:secretLength))
    }
    func writeAll(_ bytes:UnsafeRawBufferPointer) throws {
        guard let input else { throw DemoError.protocolFailure }
        var offset = 0
        while offset < bytes.count {
            let written = Darwin.write(input.fileDescriptor,bytes.baseAddress!.advanced(by:offset),bytes.count-offset)
            if written < 0 && errno == EINTR { continue }
            guard written > 0 else { throw DemoError.protocolFailure }; offset += written
        }
    }
    func send(_ message:[String:Any],secret:UnsafeRawBufferPointer? = nil) {
        do {
            let json = try JSONSerialization.data(withJSONObject:message)
            var header = [UInt8](repeating:0,count:8)
            for i in 0..<4 { header[i] = UInt8(truncatingIfNeeded:json.count >> (8*i)); header[4+i] = UInt8(truncatingIfNeeded:(secret?.count ?? 0) >> (8*i)) }
            try header.withUnsafeBytes { try writeAll($0) }; try json.withUnsafeBytes { try writeAll($0) }
            if let secret { try writeAll(secret) }
        } catch { update("The demo's Dart connection closed.") }
    }
    func command(_ name:String) { busy = name != "cancel"; syncButtons(); send(["kind":"command","command":name]) }
    @objc func checkHost() { command("check") }
    @objc func createPasskey() { command("enroll") }
    @objc func unlockTest() { command("unlock") }
    @objc func cancelOperation() { send(["kind":"command","command":"cancel"]) }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender:NSApplication) -> Bool { true }
    func applicationWillTerminate(_ notification:Notification) {
        for (_,pending) in polls { keypassCancel(pending.0); pending.1.invalidate() }
        output?.readabilityHandler = nil
        try? input?.close()
        if worker?.isRunning == true { worker?.terminate() }
    }
}
enum DemoError: Error { case protocolFailure }
let app = NSApplication.shared
let delegate = DemoHost(); app.delegate = delegate; app.setActivationPolicy(.regular)
let menu = NSMenu(); let appMenu = NSMenuItem(); menu.addItem(appMenu)
let submenu = NSMenu(); submenu.addItem(withTitle:"Quit Keypass Demo",action:#selector(NSApplication.terminate(_:)),keyEquivalent:"q")
appMenu.submenu = submenu; app.mainMenu = menu
app.run()
