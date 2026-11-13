# Swift binding

A Swift package for macOS 13+ and iOS 16+: `CInterlingua` (the C header as a
module) and `Interlingua` (the Swift API).

```swift
import Interlingua

let (secret, pub) = try Interlingua.keygen(domain: "ground-ops")
let env = try Interlingua.seal(secret: secret, recipient: nil, dst: "ground-ops",
                               label: "conf=low integ=low avail=low", nowMs: now, payload: Data("hi".utf8))
let payload = try Interlingua.open(secret: nil, keyring: pub, envelope: env)

let router = try Router(policy: policyText, keyring: keyring, node: "ground-ops")
let decision = try router.route(env, from: nil, nowMs: now)   // .verdict, .nextHop, .reason
```

Failures throw `InterlinguaError` with a stable `id`. `Router` is
`@unchecked Sendable` because the native router is thread-safe.

Build: link the static library, e.g.
`swift build -Xlinker ../../target/release/libinterlingua_ffi.a` (`make swift`).
For apps, package the library as an XCFramework (roadmap).

`interlingua-conformance` runs every vector suite, then checks the
cryptography with Apple CryptoKit (ML-DSA-87 and ML-KEM-1024 on macOS / iOS 26;
HKDF-SHA-384 and AES-GCM everywhere), including an envelope built entirely
with CryptoKit that the Rust reference must open and route.
