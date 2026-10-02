// swift-tools-version: 6.1
import PackageDescription
let package = Package(
    name: "KeypassHardwareApple",
    platforms: [.iOS(.v18), .macOS(.v13)],
    products: [.library(name: "KeypassHardwareApple", targets: ["KeypassHardwareApple"])],
    dependencies: [.package(url: "https://github.com/Yubico/yubikit-swift", exact: "1.4.0")],
    targets: [
        .target(name: "KeypassHardwareApple", dependencies: [.product(name: "YubiKit", package: "yubikit-swift")],
                path: "Sources", swiftSettings: [.swiftLanguageMode(.v5)]),
        .testTarget(name: "KeypassHardwareAppleTests", dependencies: ["KeypassHardwareApple"], path: "Tests",
                    swiftSettings: [.swiftLanguageMode(.v5)])
    ])
