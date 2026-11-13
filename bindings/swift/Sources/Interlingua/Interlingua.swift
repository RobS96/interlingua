// Swift binding of the interlingua C ABI.
//
// Byte inputs are `Data`, text is `String`, failures throw `InterlinguaError`
// carrying the stable identifier every binding reports (for example
// "BadSignature" or "Cbor/NonPreferredFloat"). Calls are synchronous: the C
// ABI's per-thread error lookup happens before control returns, so it is safe
// from any task or thread.

import CInterlingua
import Foundation

/// A failure reported by the native library.
public struct InterlinguaError: Error, CustomStringConvertible, Sendable {
    /// Negative `IL_E_*` code.
    public let code: Int32
    /// Stable identifier, e.g. `BadSignature`.
    public let id: String
    /// Human-readable detail.
    public let message: String

    public var description: String { "interlingua: \(message) [\(id)]" }
}

func take(_ buf: inout il_buf) -> Data {
    defer { il_buf_free(&buf) }
    guard let p = buf.ptr, buf.len > 0 else { return Data() }
    return Data(bytes: p, count: buf.len)
}

func check(_ rc: Int32) throws {
    if rc == IL_OK { return }
    var id = il_buf(ptr: nil, len: 0)
    var msg = il_buf(ptr: nil, len: 0)
    il_last_error_id(&id)
    il_last_error_message(&msg)
    throw InterlinguaError(
        code: rc,
        id: String(decoding: take(&id), as: UTF8.self),
        message: String(decoding: take(&msg), as: UTF8.self))
}

extension Data {
    func withBytes<R>(_ body: (UnsafePointer<UInt8>?, Int) throws -> R) rethrows -> R {
        try withUnsafeBytes { raw in try body(raw.bindMemory(to: UInt8.self).baseAddress, raw.count) }
    }
}

/// Library-level operations.
public enum Interlingua {
    /// The native library's version text.
    public static var version: String { String(cString: il_version()) }

    /// New ML-DSA-87 + ML-KEM-1024 keys: (secret bundle, public bundle).
    public static func keygen(domain: String) throws -> (secret: Data, public: Data) {
        var s = il_buf(ptr: nil, len: 0)
        var p = il_buf(ptr: nil, len: 0)
        let rc = domain.withCString { il_keygen($0, &s, &p) }
        let out = (take(&s), take(&p))
        try check(rc)
        return out
    }

    /// Build, optionally seal (when `recipient` is a public bundle), and sign.
    public static func seal(
        secret: Data, recipient: Data?, dst: String, label: String,
        contentType: String = "application/octet-stream", nowMs: UInt64,
        ttlMs: UInt64 = 3_600_000, maxHops: UInt8 = 8, payload: Data
    ) throws -> Data {
        var out = il_buf(ptr: nil, len: 0)
        let rc = secret.withBytes { sp, sl in
            (recipient ?? Data()).withBytes { rp, rl in
                payload.withBytes { pp, pl in
                    dst.withCString { d in
                        label.withCString { l in
                            contentType.withCString { c in
                                il_seal(sp, sl, rp, rl, d, l, c, nowMs, ttlMs, maxHops, pp, pl, &out)
                            }
                        }
                    }
                }
            }
        }
        let envelope = take(&out)
        try check(rc)
        return envelope
    }

    /// Throws unless a keyring key bound to the source domain signed `envelope`.
    public static func verify(keyring: Data, envelope: Data) throws {
        let rc = keyring.withBytes { kp, kl in envelope.withBytes { ep, el in il_verify(kp, kl, ep, el) } }
        try check(rc)
    }

    /// Verify, then return the plaintext (`secret` is the recipient's bundle).
    public static func open(secret: Data?, keyring: Data, envelope: Data) throws -> Data {
        var out = il_buf(ptr: nil, len: 0)
        let rc = (secret ?? Data()).withBytes { sp, sl in
            keyring.withBytes { kp, kl in
                envelope.withBytes { ep, el in il_open(sp, sl, kp, kl, ep, el, &out) }
            }
        }
        let payload = take(&out)
        try check(rc)
        return payload
    }

    /// Strict deterministic CBOR: decode and re-encode.
    public static func cborCanonical(_ input: Data) throws -> Data {
        var out = il_buf(ptr: nil, len: 0)
        let rc = input.withBytes { il_cbor_canonical($0, $1, &out) }
        let bytes = take(&out)
        try check(rc)
        return bytes
    }

    /// RFC 8949 diagnostic notation.
    public static func cborDiag(_ input: Data) throws -> String {
        var out = il_buf(ptr: nil, len: 0)
        let rc = input.withBytes { il_cbor_diag($0, $1, &out) }
        let text = take(&out)
        try check(rc)
        return String(decoding: text, as: UTF8.self)
    }

    /// Canonical text and CBOR forms of a label.
    public static func normalizeLabel(_ label: String) throws -> (text: String, cbor: Data) {
        var t = il_buf(ptr: nil, len: 0)
        var c = il_buf(ptr: nil, len: 0)
        let rc = label.withCString { il_label_normalize($0, &t, &c) }
        let out = (String(decoding: take(&t), as: UTF8.self), take(&c))
        try check(rc)
        return out
    }
}

/// A CCSDS 133.0-B-2 Space Packet.
public struct SpacePacket: Equatable, Sendable {
    public var telecommand: Bool
    public var secondaryHeader: Bool
    public var apid: UInt16
    /// 0 continuation, 1 first, 2 last, 3 unsegmented.
    public var sequenceFlags: UInt8
    public var sequenceCount: UInt16
    public var data: Data

    public init(telecommand: Bool, secondaryHeader: Bool, apid: UInt16, sequenceFlags: UInt8, sequenceCount: UInt16, data: Data) {
        self.telecommand = telecommand
        self.secondaryHeader = secondaryHeader
        self.apid = apid
        self.sequenceFlags = sequenceFlags
        self.sequenceCount = sequenceCount
        self.data = data
    }

    public func encode() throws -> Data {
        var out = il_buf(ptr: nil, len: 0)
        let rc = data.withBytes {
            il_ccsds_packet_encode(telecommand ? 1 : 0, secondaryHeader ? 1 : 0, apid, sequenceFlags, sequenceCount, $0, $1, &out)
        }
        let bytes = take(&out)
        try check(rc)
        return bytes
    }

    /// Decode the packet at the start of `bytes`; returns it and its length.
    public static func decode(_ bytes: Data) throws -> (SpacePacket, Int) {
        var tc: UInt8 = 0, sec: UInt8 = 0, flags: UInt8 = 0
        var apid: UInt16 = 0, count: UInt16 = 0
        var used = 0
        var data = il_buf(ptr: nil, len: 0)
        let rc = bytes.withBytes { il_ccsds_packet_decode($0, $1, &tc, &sec, &apid, &flags, &count, &used, &data) }
        let payload = take(&data)
        try check(rc)
        return (SpacePacket(telecommand: tc != 0, secondaryHeader: sec != 0, apid: apid, sequenceFlags: flags, sequenceCount: count, data: payload), used)
    }
}

/// A router's answer for one envelope.
public struct Decision: Sendable {
    public let verdict: String
    public let nextHop: String
    public let reason: String
    public let auditLine: String
    public let forward: Data
}

/// A router for one trust domain. The native router is thread-safe.
public final class Router: @unchecked Sendable {
    private let handle: OpaquePointer

    public init(policy: String, keyring: Data, node: String) throws {
        var h: OpaquePointer?
        let rc = policy.withCString { p in
            keyring.withBytes { kp, kl in node.withCString { n in il_router_new(p, kp, kl, n, &h) } }
        }
        try check(rc)
        guard let h else { throw InterlinguaError(code: -1, id: "InvalidArgument", message: "no router") }
        handle = h
    }

    deinit { il_router_free(handle) }

    /// Decide for `envelope`; `from` is nil when a local sender hands it over.
    public func route(_ envelope: Data, from: String?, nowMs: UInt64) throws -> Decision {
        var line = il_buf(ptr: nil, len: 0)
        var fwd = il_buf(ptr: nil, len: 0)
        let rc = envelope.withBytes { ep, el in
            if let from {
                return from.withCString { il_router_route(handle, ep, el, $0, nowMs, &line, &fwd) }
            }
            return il_router_route(handle, ep, el, nil, nowMs, &line, &fwd)
        }
        let text = String(decoding: take(&line), as: UTF8.self)
        let forward = take(&fwd)
        try check(rc)
        func field(_ key: String) -> String {
            text.split(separator: " ").first { $0.hasPrefix(key + "=") }.map { String($0.dropFirst(key.count + 1)) } ?? ""
        }
        return Decision(verdict: field("verdict"), nextHop: field("next"), reason: field("reason"), auditLine: text, forward: forward)
    }
}
