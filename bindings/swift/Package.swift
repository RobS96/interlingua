// swift-tools-version: 6.0
//
// Swift binding of the interlingua C ABI (macOS, iOS). The native library is
// linked statically; for local builds pass it to the linker, e.g.
//   swift build -Xlinker ../../target/release/libinterlingua_ffi.a
// (`make swift` does this). For apps, ship it as an XCFramework (docs/ROADMAP.md).
import PackageDescription

let package = Package(
    name: "Interlingua",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "Interlingua", targets: ["Interlingua"]),
        .executable(name: "interlingua-conformance", targets: ["interlingua-conformance"]),
    ],
    targets: [
        .systemLibrary(name: "CInterlingua", path: "Sources/CInterlingua"),
        .target(name: "Interlingua", dependencies: ["CInterlingua"]),
        .executableTarget(name: "interlingua-conformance", dependencies: ["Interlingua"]),
    ]
)
