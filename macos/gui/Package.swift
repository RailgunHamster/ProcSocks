// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ProcSocksMenuBar",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "ProcSocksMenuBar", targets: ["ProcSocksMenuBar"])],
    targets: [
        .target(name: "ProcSocksKit"),
        .executableTarget(name: "ProcSocksMenuBar", dependencies: ["ProcSocksKit"]),
        .testTarget(name: "ProcSocksKitTests", dependencies: ["ProcSocksKit"])
    ]
)
