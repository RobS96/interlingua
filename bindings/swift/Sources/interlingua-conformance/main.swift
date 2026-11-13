// Swift conformance runner: the shared vectors through the Swift binding, then
// independent checks with Apple CryptoKit (macOS/iOS 26: ML-DSA-87,
// ML-KEM-1024; HKDF-SHA-384 and AES-GCM on any version).
//
//   interlingua-conformance <vectors-dir>

import CryptoKit
import Foundation
import Interlingua

var passed = 0
var failed = 0

@MainActor func check(_ ok: Bool, _ what: @autoclosure () -> String) {
    if ok { passed += 1 } else { failed += 1; FileHandle.standardError.write(Data("FAIL \(what())\n".utf8)) }
}

guard CommandLine.arguments.count == 2 else {
    FileHandle.standardError.write(Data("usage: interlingua-conformance <vectors-dir>\n".utf8))
    exit(64)
}
let dir = URL(fileURLWithPath: CommandLine.arguments[1])

@MainActor func read(_ name: String) -> Data {
    guard let d = try? Data(contentsOf: dir.appendingPathComponent(name)) else {
        FileHandle.standardError.write(Data("cannot read \(name)\n".utf8))
        exit(66)
    }
    return d
}

@MainActor func text(_ name: String) -> String { String(decoding: read(name), as: UTF8.self) }

func unhex(_ s: String) -> Data {
    var out = Data(capacity: s.utf8.count / 2)
    var high: UInt8?
    for c in s.utf8 {
        let v: UInt8
        switch c {
        case 48...57: v = c - 48
        case 97...102: v = c - 87
        case 65...70: v = c - 55
        default: continue
        }
        if let h = high { out.append(h << 4 | v); high = nil } else { high = v }
    }
    return out
}

func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

struct Record {
    var section: String
    var fields: [String: String]
    subscript(_ k: String) -> String { fields[k] ?? "" }
}

@MainActor func parse(_ name: String) -> [Record] {
    var out: [Record] = []
    var section = ""
    var cur: [String: String] = [:]
    func flush() { if !cur.isEmpty { out.append(Record(section: section, fields: cur)); cur = [:] } }
    for raw in text(name).split(separator: "\n", omittingEmptySubsequences: false) {
        let line = raw.trimmingCharacters(in: .whitespaces)
        if line.hasPrefix("#") { continue }
        if line.isEmpty { flush(); continue }
        if line.hasPrefix("["), line.hasSuffix("]") {
            flush()
            section = String(line.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
            continue
        }
        guard let eq = line.firstIndex(of: "=") else { continue }
        cur[line[..<eq].trimmingCharacters(in: .whitespaces)] = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
    }
    flush()
    return out
}

func errorID(_ body: () throws -> Void) -> String? {
    do { try body(); return nil } catch let e as InterlinguaError { return e.id } catch { return "\(error)" }
}

// ---- the shared vectors --------------------------------------------------

for r in parse("cbor.rsp") {
    let input = unhex(r["cbor"])
    if r["expect"] == "accept" {
        check((try? Interlingua.cborCanonical(input)) == input, "cbor \(r["cbor"])")
        if let want = r.fields["diag"] { check((try? Interlingua.cborDiag(input)) == want, "cbor diag \(want)") }
    } else {
        check(errorID { _ = try Interlingua.cborCanonical(input) } == r["error"], "cbor reject \(r["cbor"])")
    }
}

for r in parse("label.rsp") {
    if r["expect"] == "accept" {
        let got = try? Interlingua.normalizeLabel(r["text"])
        check(got?.text == r["canonical"] && got?.cbor == unhex(r["cbor"]), "label \(r["text"])")
    } else {
        check(errorID { _ = try Interlingua.normalizeLabel(r["text"]) } == r["error"], "label reject \(r["text"])")
    }
}

let flagCodes: [String: UInt8] = ["continuation": 0, "first": 1, "last": 2, "unsegmented": 3]
for r in parse("ccsds.rsp") {
    let wire = unhex(r["packet"])
    if r["expect"] == "accept" {
        let want = SpacePacket(
            telecommand: r["type"] == "tc", secondaryHeader: r["sec"] == "1", apid: UInt16(r["apid"]) ?? 0,
            sequenceFlags: flagCodes[r["flags"]] ?? 9, sequenceCount: UInt16(r["count"]) ?? 0, data: unhex(r["data"]))
        let got = try? SpacePacket.decode(wire)
        check(got?.0 == want && got?.1 == wire.count, "ccsds decode \(r["packet"])")
        check((try? want.encode()) == wire, "ccsds encode \(r["packet"])")
    } else {
        check(errorID { _ = try SpacePacket.decode(wire) } == r["error"], "ccsds reject \(r["packet"])")
    }
}

let ring = read("keyring.pub")
let secrets = text("test-secrets.txt")

@MainActor func secret(for domain: String) -> Data {
    let magic = "interlingua-secret-key v1\n"
    for chunk in secrets.components(separatedBy: magic).dropFirst() where chunk.hasPrefix("domain \(domain)\n") {
        return Data((magic + chunk).utf8)
    }
    FileHandle.standardError.write(Data("no test key for \(domain)\n".utf8))
    exit(65)
}

for r in parse("envelope.rsp") {
    let key = r.fields["recipient"].map { secret(for: $0) }
    let envelope = unhex(r["envelope"])
    if r["expect"] == "valid" {
        check((try? Interlingua.open(secret: key, keyring: ring, envelope: envelope)) == unhex(r["payload"]), "envelope \(r["name"])")
    } else {
        let want = String(r["expect"].dropFirst("error:".count))
        check(errorID { _ = try Interlingua.open(secret: key, keyring: ring, envelope: envelope) } == want, "envelope \(r["name"])")
    }
}

let policy = text("routing-policy.ndb")
var routers: [String: Router] = [:]
var section: String?
var forwarded = Data()
for r in parse("routing.rsp") {
    if section != r.section { routers = [:]; forwarded = Data(); section = r.section }
    let node = r["node"]
    if routers[node] == nil { routers[node] = try Router(policy: policy, keyring: ring, node: node) }
    let envelope = r["envelope"] == "forwarded" ? forwarded : unhex(r["envelope"])
    let from = r["from"] == "-" ? nil : r["from"]
    guard let decision = try? routers[node]?.route(envelope, from: from, nowMs: UInt64(r["now"]) ?? 0) else {
        check(false, "routing [\(r.section)] \(r["name"]): no decision")
        continue
    }
    var got = decision.verdict
    if got == "forward" { got += ":" + decision.nextHop }
    if got == "reject" { got += ":" + decision.reason }
    check(got == r["expect"], "routing [\(r.section)] \(r["name"]): wanted \(r["expect"]), got \(got)")
    forwarded = decision.forward
}
let sharedVectors = passed

// ---- independent checks with Apple CryptoKit -----------------------------

struct DomainKeys { var name: String; var pk = Data(); var ek = Data() }
var keyring: [DomainKeys] = []
for line in text("keyring.pub").split(separator: "\n") {
    let parts = line.split(separator: " ", maxSplits: 1).map(String.init)
    guard parts.count == 2 else { continue }
    switch parts[0] {
    case "domain": keyring.append(DomainKeys(name: parts[1]))
    case "mldsa87-pk": keyring[keyring.count - 1].pk = unhex(parts[1])
    case "mlkem1024-ek": keyring[keyring.count - 1].ek = unhex(parts[1])
    default: break
    }
}
@MainActor func keys(_ domain: String) -> DomainKeys { keyring.first { $0.name == domain } ?? DomainKeys(name: domain) }

/// A minimal deterministic CBOR writer: what an envelope needs.
struct CBOR {
    var bytes = Data()
    mutating func head(_ major: UInt8, _ n: UInt64) {
        let m = major << 5
        switch n {
        case 0..<24: bytes.append(m | UInt8(n))
        case 24...0xff: bytes.append(contentsOf: [m | 24, UInt8(n)])
        case 0x100...0xffff: bytes.append(m | 25); bytes.append(contentsOf: withUnsafeBytes(of: UInt16(n).bigEndian, Array.init))
        case 0x10000...0xffff_ffff: bytes.append(m | 26); bytes.append(contentsOf: withUnsafeBytes(of: UInt32(n).bigEndian, Array.init))
        default: bytes.append(m | 27); bytes.append(contentsOf: withUnsafeBytes(of: n.bigEndian, Array.init))
        }
    }
    mutating func uint(_ n: UInt64) { head(0, n) }
    mutating func data(_ d: Data) { head(2, UInt64(d.count)); bytes.append(d) }
    mutating func text(_ s: String) { head(3, UInt64(s.utf8.count)); bytes.append(contentsOf: s.utf8) }
}

func sha384(_ d: Data) -> Data { Data(SHA384.hash(data: d)) }

// HKDF-SHA-384 + AES-256-GCM against the sealed vector's intermediates (any macOS).
for r in parse("envelope.rsp") where r["expect"] == "valid" && !r["kem-ss"].isEmpty {
    let aad = unhex(r["aead-aad"])
    let headerStart = 2 + 11 // array(2), text(11) "IL1-Encrypt"
    let (offset, length): (Int, Int) = aad[aad.startIndex + headerStart] == 0x58
        ? (headerStart + 2, Int(aad[aad.startIndex + headerStart + 1]))
        : (headerStart + 3, Int(aad[aad.startIndex + headerStart + 1]) << 8 | Int(aad[aad.startIndex + headerStart + 2]))
    let protected = aad.subdata(in: (aad.startIndex + offset)..<(aad.startIndex + offset + length))
    let info = Data("IL1-Seal-AES256GCM".utf8) + sha384(keys(r["recipient"]).ek)
    let okm = HKDF<SHA384>.deriveKey(inputKeyMaterial: SymmetricKey(data: unhex(r["kem-ss"])), salt: sha384(protected), info: info, outputByteCount: 44)
    let okmBytes = okm.withUnsafeBytes { Data($0) }
    check(hex(okmBytes) == r["aead-key"] + r["aead-nonce"], "CryptoKit HKDF-SHA-384 matches the Rust derivation")
    let sealed = unhex(r["aead-ct"])
    let plain = try? AES.GCM.open(
        AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: okmBytes.suffix(12)), ciphertext: sealed.dropLast(16), tag: sealed.suffix(16)),
        using: SymmetricKey(data: okmBytes.prefix(32)), authenticating: aad)
    check(plain == unhex(r["payload"]), "CryptoKit AES-256-GCM opens the Rust-sealed payload")
}

var cryptoKitNote = "CryptoKit ML-DSA/ML-KEM checks skipped (they need macOS 26 or iOS 26)"
if #available(macOS 26.0, iOS 26.0, *) {
    cryptoKitNote = "CryptoKit ML-DSA-87 + ML-KEM-1024 checks ran"
    // FIPS 204 key generation from the published seeds 0x01…01 … 0x06…06.
    for (i, k) in keyring.enumerated() {
        let pk = try? MLDSA87.PrivateKey(seedRepresentation: Data(repeating: UInt8(i + 1), count: 32), publicKey: nil).publicKey.rawRepresentation
        check(pk == k.pk, "CryptoKit derives \(k.name)'s ML-DSA-87 key from seed \(i + 1)")
        check((try? MLKEM1024.PublicKey(rawRepresentation: k.ek)) != nil, "CryptoKit accepts \(k.name)'s ML-KEM-1024 key")
    }
    // Rust-made signatures verify in CryptoKit.
    for r in parse("envelope.rsp") where r["expect"] == "valid" {
        let pk = try? MLDSA87.PublicKey(rawRepresentation: keys(r["signer"]).pk)
        check(pk?.isValidSignature(unhex(r["signature"]), for: unhex(r["signed"])) == true, "CryptoKit verifies \(r["name"])")
    }
    // An envelope built entirely with CryptoKit opens and routes in the Rust reference.
    do {
        let t0: UInt64 = 1_767_225_600_000
        let created = t0 + 5_000
        let signer = try MLDSA87.PrivateKey(seedRepresentation: Data(repeating: 1, count: 32), publicKey: nil) // ground-ops
        let recipientEK = keys("space-segment").ek
        var id = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        for i in 0..<6 { id[i] = UInt8(truncatingIfNeeded: created >> (8 * (5 - UInt64(i)))) }
        id[6] = 0x70 | (id[6] & 0x0f)
        id[8] = 0x80 | (id[8] & 0x3f)

        var h = CBOR()
        h.head(5, 12)
        h.uint(1); h.uint(1)
        h.uint(2); h.uint(1)
        h.uint(3); h.data(id)
        h.uint(4); h.text("ground-ops")
        h.uint(5); h.text("space-segment")
        h.uint(6); h.head(4, 4); h.uint(2); h.uint(3); h.uint(3); h.head(4, 1); h.text("tt-c")
        h.uint(7); h.uint(created)
        h.uint(8); h.uint(created + 3_600_000)
        h.uint(9); h.uint(8)
        h.uint(10); h.text("text/plain")
        h.uint(11); h.bytes.append(0xf5)
        h.uint(12); h.data(sha384(signer.publicKey.rawRepresentation))
        let protected = h.bytes

        let kem = try MLKEM1024.PublicKey(rawRepresentation: recipientEK).encapsulate()
        let okm = HKDF<SHA384>.deriveKey(
            inputKeyMaterial: kem.sharedSecret, salt: sha384(protected),
            info: Data("IL1-Seal-AES256GCM".utf8) + sha384(recipientEK), outputByteCount: 44
        ).withUnsafeBytes { Data($0) }
        var aad = CBOR()
        aad.head(4, 2); aad.text("IL1-Encrypt"); aad.data(protected)
        let message = Data("built by Apple CryptoKit".utf8)
        let box = try AES.GCM.seal(message, using: SymmetricKey(data: okm.prefix(32)), nonce: AES.GCM.Nonce(data: okm.suffix(12)), authenticating: aad.bytes)
        var sealed = CBOR()
        sealed.head(4, 3); sealed.data(sha384(recipientEK)); sealed.data(kem.encapsulated); sealed.data(box.ciphertext + box.tag)

        var toSign = CBOR()
        toSign.head(4, 3); toSign.text("IL1-Sign"); toSign.data(protected); toSign.data(sealed.bytes)
        let signature = try signer.signature(for: toSign.bytes)
        var envelope = CBOR()
        envelope.head(4, 4); envelope.data(protected); envelope.head(5, 1); envelope.uint(1); envelope.uint(8)
        envelope.data(sealed.bytes); envelope.data(signature)

        let opened = try? Interlingua.open(secret: secret(for: "space-segment"), keyring: ring, envelope: envelope.bytes)
        check(opened == message, "the Rust reference opens a CryptoKit-built envelope")
        let decision = try Router(policy: policy, keyring: ring, node: "ground-ops").route(envelope.bytes, from: nil, nowMs: t0 + 6_000)
        check(decision.verdict == "forward" && decision.nextHop == "relay-alpha", "the Rust router forwards a CryptoKit-built envelope")
    } catch {
        check(false, "building an envelope with CryptoKit: \(error)")
    }
}

print("Swift binding (\(Interlingua.version)): \(sharedVectors) shared-vector checks, \(passed - sharedVectors) CryptoKit checks, \(failed) failed")
print(cryptoKitNote)
exit(failed == 0 ? 0 : 1)
