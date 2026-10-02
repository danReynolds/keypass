// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "KeypassNative",
    platforms: [.macOS("15.0"), .iOS("18.0")],
    products: [.library(name: "KeypassNative", type: .dynamic, targets: ["KeypassNative"])],
    targets: [
        .target(name: "KeypassNative", path: ".", exclude: ["SmokeHost", "DemoHost", "Tests", "README.md", "PlatformPrfProbe.swift"], sources: ["Keypass.swift"]),
        .testTarget(name: "KeypassNativeTests", dependencies: ["KeypassNative"], path: "Tests"),
    ])
