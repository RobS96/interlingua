# interlingua wire format and processing rules

**Version 1 · algorithm suite 1 (IL1-CNSA2) · status: draft for review**

This document is normative. The key words MUST, MUST NOT, REQUIRED, SHALL,
SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be interpreted as in
BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in capitals.
The machine-readable schema is [`spec/interlingua.cddl`](../spec/interlingua.cddl)
(CDDL, RFC 8610). Conformance is defined by the vectors in
[`spec/vectors/`](../spec/vectors) (section 11).

## Contents

1. [Purpose and model](#1-purpose-and-model)
2. [Notation](#2-notation)
3. [Deterministic CBOR profile](#3-deterministic-cbor-profile)
4. [Identifiers and text](#4-identifiers-and-text)
5. [Security labels](#5-security-labels)
6. [Envelope](#6-envelope)
7. [Suite IL1-CNSA2: keys, signatures, sealing](#7-suite-il1-cnsa2-keys-signatures-sealing)
8. [Router processing](#8-router-processing)
9. [Error identifiers and reason codes](#9-error-identifiers-and-reason-codes)
10. [CCSDS Space Packet framing](#10-ccsds-space-packet-framing)
11. [Conformance](#11-conformance)
12. [Security considerations](#12-security-considerations)
13. [Extension and versioning](#13-extension-and-versioning)
14. [References](#14-references)

## 1. Purpose and model

interlingua moves messages between **trust domains**: administrative or
security boundaries named by the operator (for example `ground-ops`,
`space-segment`). Every message is an **envelope**: a signed header, an
optional sealed payload, and a signature that every implementation, in every
language, checks over the same bytes.

A **router** serves one domain (its *node*). It accepts envelopes from local
senders or from neighbouring domains and decides, under a **policy**, to
deliver, forward or reject each one, writing one hash-chained audit record
per decision.

The design rule behind the name: each language converts to and from **one
canonical form** (an *interlingua*, as in interlingua-based machine
translation), so N languages need N codecs rather than N×(N−1)/2 pairwise
translators, and agreement between any two of them is checked against the
same test vectors rather than against each other.

## 2. Notation

* `‖` is byte-string concatenation; `len(x)` is the length in bytes.
* `det-CBOR(v)` is the encoding of `v` under section 3.
* `SHA-384(x)` is FIPS 180-4 SHA-384.
* Arrays and maps are written in CBOR diagnostic notation (RFC 8949 §8).
* Times are Unix milliseconds (UTC, leap seconds not counted), unsigned.

## 3. Deterministic CBOR profile

All structures are CBOR (RFC 8949) restricted to this data model: unsigned
and negative integers (major types 0 and 1), byte strings (2), text strings
(3), arrays (4), maps (5), `false`, `true`, `null`, and floating-point
numbers. Tags (major type 6), `undefined`, and every other simple value are
**not** part of the model.

**Encoders** MUST produce RFC 8949 §4.2.1 Core Deterministic Encoding:

* integers, lengths and counts in the shortest form;
* definite lengths only;
* map entries sorted by the bytewise lexicographic order of their encoded
  keys, with no duplicate keys;
* floating-point values in the shortest IEEE 754-2019 width (binary16,
  binary32, binary64) that represents the value exactly, and every NaN as the
  single encoding `0xf97e00`.

**Decoders** MUST reject, with the error identifier in brackets:

| Input | Error |
|---|---|
| input ending inside an item | `Cbor/Truncated` |
| bytes after the single top-level item | `Cbor/TrailingBytes` |
| a non-shortest integer, length or count | `Cbor/NonCanonicalInteger` |
| an indefinite length, or a stray `break` (`0xff`) | `Cbor/IndefiniteLength` |
| additional information 28–30 | `Cbor/ReservedInfo` |
| a tag | `Cbor/UnsupportedTag` |
| `undefined` or another simple value | `Cbor/UnsupportedSimple` |
| a float that a narrower width represents exactly | `Cbor/NonPreferredFloat` |
| a NaN other than `0xf97e00` | `Cbor/NonCanonicalNaN` |
| map keys out of order | `Cbor/UnsortedMapKeys` |
| a repeated map key | `Cbor/DuplicateMapKey` |
| a text string that is not UTF-8 | `Cbor/InvalidUtf8` |
| nesting deeper than 16 | `Cbor/DepthExceeded` |
| a container with more than 4096 items | `Cbor/TooManyItems` |
| an input or string over 16 MiB | `Cbor/TooLarge` |

Consequence: for every accepted input `x`, `det-CBOR(decode(x)) = x`. Two
implementations therefore cannot disagree about which bytes a signature
covers (no parser differential), which is the property the rest of this
specification depends on. Note that RFC 7049's "canonical" length-first map
ordering is **not** this order and is rejected.

## 4. Identifiers and text

Identifiers are lowercase ASCII, so two implementations never disagree about
whether two names are equal (no Unicode normalization, no confusables):

| Kind | Syntax |
|---|---|
| domain | 1–63 of `a-z 0-9 -`, starting with a letter, not ending with `-` |
| compartment | 1–32 of `a-z 0-9 . -`, starting with a letter or digit |
| media type | `type/subtype`, each part 1–63 of `a-z 0-9 ! # $ & ^ _ . + -` starting with a letter or digit (RFC 6838 restricted names), no parameters |

Text payloads SHOULD be UTF-8 (RFC 3629) without a byte-order mark. Payloads
are opaque to this specification.

## 5. Security labels

A label is a FIPS 199 security category, one potential-impact value for each
security objective, plus need-to-know compartments:

```
label = [confidentiality, integrity, availability, [* compartment]]
impact: 0 = not applicable, 1 = low, 2 = moderate, 3 = high
```

* Integrity and availability MUST be at least `low` (FIPS 199 allows "not
  applicable" for the confidentiality of public information only).
* Compartments MUST be sorted bytewise, unique, at most 16.
* The text form is `conf=<n/a|low|moderate|high> integ=<…> avail=<…>
  [comp=a,b]`; parsers accept the terms in any order, and the canonical text
  lists them in that order with sorted compartments.

## 6. Envelope

```
envelope = [protected: bstr, unprotected: {1: hops}, payload: bstr, signature: bstr]
```

`protected` holds `det-CBOR(header)`. Receivers MUST decode it strictly and
MUST verify the signature over the bytes received, never over a re-encoding.

**Header** (a map with exactly the keys 1–12):

| Key | Field | Type and rule |
|---|---|---|
| 1 | version | 1. A receiver MUST check this key first and report `Version` for any other value. |
| 2 | suite | 1 (IL1-CNSA2). Other values: `Suite`. |
| 3 | id | 16 bytes, a UUID version 7 (RFC 9562): 48-bit creation time in ms, version `7`, variant `10`. |
| 4 | src | domain of the sender |
| 5 | dst | domain of the final recipient |
| 6 | label | section 5 |
| 7 | created | Unix ms |
| 8 | expires | Unix ms, MUST be greater than `created` |
| 9 | max_hops | 1–64: forwarding hops the sender allows |
| 10 | content_type | media type of the plaintext payload |
| 11 | sealed | `true` when the payload is sealed (section 7.4) |
| 12 | signer | SHA-384 of the signer's raw ML-DSA-87 public key (48 bytes) |

**Unprotected header**: exactly `{1: hops}`, `hops` 0–255. It is the only
field a router changes (decrementing it when forwarding) and it is not
signed; a router MUST reject `hops > max_hops` (`HopCountInflated`), so the
signed `max_hops` bounds it. Unknown unprotected keys MUST be rejected
(`Schema`).

**Signature**: 4627 bytes (section 7.3).

## 7. Suite IL1-CNSA2: keys, signatures, sealing

### 7.1 Algorithms

| Purpose | Algorithm | Standard |
|---|---|---|
| Signatures | ML-DSA-87, pure mode, empty context | FIPS 204 |
| Key establishment | ML-KEM-1024 | FIPS 203 |
| Key derivation | HKDF with SHA-384 | RFC 5869, SP 800-56C Rev. 2 |
| Encryption | AES-256-GCM, 96-bit nonce, 128-bit tag | FIPS 197, SP 800-38D |
| Hash, key identifiers | SHA-384 | FIPS 180-4 |

This is the NSA CNSA 2.0 suite for these functions; there is one suite per
version and no negotiation, so there is nothing to downgrade.

### 7.2 Keys and key identifiers

Each domain holds one ML-DSA-87 key pair (signing) and one ML-KEM-1024 key
pair (receiving sealed payloads). A **key identifier** is `SHA-384(raw public
key)`. A keyring binds each public key to exactly one domain; a key MUST NOT
be accepted for any other domain.

The reference key bundle format is text, one `name value` pair per line,
binary values in lowercase hex:

```
interlingua-public-key v1          interlingua-secret-key v1
domain <domain>                    domain <domain>
suite IL1-CNSA2                    suite IL1-CNSA2
mldsa87-pk <2592 bytes>            mldsa87-pkcs8 <PKCS#8 v1 DER, seed form>
mlkem1024-ek <1568 bytes>          mlkem1024-dk <3168 bytes, FIPS 203 expanded>
```

An implementation loading an expanded ML-KEM decapsulation key MUST apply the
FIPS 203 §7.3 hash check (the SHA3-256 of the embedded encapsulation key
equals the stored hash) and SHOULD run a pairwise-consistency test.

### 7.3 Signature

```
signature = ML-DSA-87.Sign(sk, det-CBOR(["IL1-Sign", protected, payload]), ctx = "")
```

Signing SHOULD use the hedged (randomized) variant of FIPS 204; the
deterministic variant is permitted. Domain separation comes from the
`"IL1-Sign"` string in the signed structure, so any FIPS 204 implementation,
including those without context-string support, can verify. Verification
MUST use the key whose identifier equals `header.signer`, and that key MUST be
bound to `header.src` in the verifier's keyring.

### 7.4 Sealing

When `header.sealed` is true, the payload is
`det-CBOR([recipient, kem_ciphertext, aead])`, built as follows from the
recipient domain's ML-KEM-1024 encapsulation key `ek`:

```
recipient           = SHA-384(ek)                                   ; 48 bytes
(K, kem_ciphertext) = ML-KEM-1024.Encaps(ek)                        ; 32-byte K, 1568-byte ciphertext
OKM                 = HKDF-SHA-384(IKM = K,
                                   salt = SHA-384(protected),
                                   info = "IL1-Seal-AES256GCM" ‖ recipient,
                                   L = 44)
key, nonce          = OKM[0..32], OKM[32..44]
aad                 = det-CBOR(["IL1-Encrypt", protected])
aead                = AES-256-GCM-Encrypt(key, nonce, aad, plaintext)   ; ciphertext ‖ 16-byte tag
```

Every message performs a fresh encapsulation, so every message has its own
key and the derived nonce is never reused under a key. Binding the protected
header into the salt and the associated data means a sealed payload cannot be
moved under another header. The signature (7.3) covers the sealed payload.

To open: check `recipient` against the local key (`WrongRecipient`),
decapsulate, derive, and authenticate-decrypt (`Decrypt` on any failure).
Receivers MUST verify the signature before opening.

## 8. Router processing

A router serves one domain, the **node**, under one policy (the policy
language is in [POLICY.md](POLICY.md)). For each envelope it evaluates the
checks below **in order** and stops at the first that fails, with that reason.
Only if all pass does it change state (replay cache, rate tokens) and accept.
`now` and the clock-skew allowance `skew` come from the router; `max_lifetime`
and `seal_at` from the policy.

| # | Check | Reason on failure |
|---|---|---|
| 1 | The envelope decodes (sections 3, 6) | `Malformed` |
| 2 | `src` is a policy domain | `UnknownSourceDomain` |
| 3 | `dst` is a policy domain | `UnknownDestinationDomain` |
| 4 | Arrival: with no previous hop, `src` is the node; otherwise the route previous→node exists, allows the label and the envelope size | `UnexpectedArrival` |
| 5 | `header.signer` is in the keyring | `UnknownSigner` |
| 6 | that key is bound to `src` | `SignerNotAuthorized` |
| 7 | the signature verifies | `BadSignature` |
| 8 | `created ≤ now + skew` | `NotYetValid` |
| 9 | `now ≤ expires + skew` | `Expired` |
| 10 | `expires − created ≤ max_lifetime` | `LifetimeTooLong` |
| 11 | `hops ≤ max_hops` | `HopCountInflated` |
| 12 | `label.conf ≤ src.conf` | `ConfidentialityExceedsSource` |
| 13 | `label.integ ≤ src.integ` (a source cannot vouch above itself) | `IntegrityExceedsSource` |
| 14 | `label.conf ≤ dst.conf` (Bell–LaPadula: the destination is cleared) | `ConfidentialityExceedsDestination` |
| 15 | `label.integ ≥ dst.integ_floor` (Biba: no low-integrity data flows up) | `IntegrityBelowFloor` |
| 16 | label compartments ⊆ both `src` and `dst` compartments | `CompartmentNotPermitted` |
| 17 | sealed if `label.conf ≥ seal_at` or `dst` requires sealing | `EncryptionRequired` |
| 18 | if sealed, `recipient` is an encapsulation key bound to `dst` | `SealedToWrongRecipient` |
| 19 | if the node is not `dst`: `hops ≥ 1` | `HopLimitExceeded` |
| 20 | if the node is not `dst`: a path exists (8.1) | `PayloadTooLarge` if one exists ignoring size limits, else `NoRoute` |
| 21 | the path needs no more than `hops` hops | `HopLimitExceeded` |
| 22 | `id` is not in this router's replay cache | `Replay` |
| 23 | the replay cache has room | `Overloaded` |
| 24 | `src` has a rate token at this router (8.2) | `RateLimited` |

On acceptance the router records `id` until `expires + skew`, then
**delivers** (node = `dst`) or **forwards** to the next hop with `hops`
decremented and every other byte unchanged.

### 8.1 Path selection

Breadth-first search from the node over policy routes. An edge is usable when
`label.conf ≤ route.max_conf`, label compartments ⊆ route compartments, the
envelope is sealed if the route requires it, and the envelope fits
`route.max_bytes`. A relay (any domain on the path other than the endpoints)
must be able to hold the label: `label.conf ≤ conf`, compartments held,
`label.integ ≥ integ_floor`. Neighbours are visited in bytewise name order,
so every implementation chooses the same shortest path.

### 8.2 Rate limiting

A token bucket per source domain per router: capacity `burst` tokens,
refilled at `rate` tokens per second, computed in integer milli-tokens from
`now` so that results are reproducible.

### 8.3 Audit records

Every decision, accepted or not, produces one line:

```
audit seq=<n> time=<ms> node=<d> from=<d|-> id=<uuid|-> src=<d|-> dst=<d|->
      conf=… integ=… avail=… comp=<list|-> sealed=<yes|no|-> auth=<verified|unverified>
      bytes=<n> env=sha384:<hex> verdict=<deliver|forward|reject> next=<d|->
      reason=<ok|Reason> code=<0|100-199> prev=sha384:<hex> hash=sha384:<hex>
```

(one line in practice; wrapped here). `hash` is SHA-384 of the line up to,
not including, ` hash=`; `prev` is the previous line's `hash`, 96 zeros for
the first. Values are single tokens; characters outside printable ASCII, and
`=`, are written as `?`. Fields from a header that failed verification are
claims, marked by `auth=unverified`.

## 9. Error identifiers and reason codes

**Errors** (API and C ABI; the identifier is what conformance vectors and
every binding compare):

| Code | Identifier | Meaning |
|---|---|---|
| −1 | `InvalidArgument` | API misuse (NULL, length, range) |
| −10 | `Cbor/<detail>` | section 3 |
| −11 | `Schema` | well-formed CBOR, wrong structure |
| −12 | `Version` | unsupported wire version |
| −13 | `Suite` | unsupported algorithm suite |
| −20 | `Identifier` | section 4 |
| −21 | `Label` | section 5 |
| −30 | `Crypto` | a primitive failed (random generator, key generation) |
| −31 | `BadSignature` | the signature does not verify |
| −32 | `UnknownSigner` | the signing key is not in the keyring |
| −33 | `SignerNotAuthorized` | the key is bound to another domain |
| −34 | `Decrypt` | decapsulation or AEAD authentication failed |
| −35 | `WrongRecipient` | sealed to another key |
| −36 | `KeyRequired` | sealed, and no key was supplied |
| −40 | `Key` | a key or bundle is malformed |
| −50 | `Policy` | the policy does not parse or validate |
| −60 | `Ccsds` | a Space Packet is malformed or out of sequence |
| −70 | `Vector` | a conformance vector is malformed |
| −99 | `Panic` | a bug, caught at the C boundary |

**Router reasons**: `Malformed` 100, `UnknownSourceDomain` 101,
`UnknownDestinationDomain` 102, `UnknownSigner` 103, `SignerNotAuthorized`
104, `BadSignature` 105, `Expired` 106, `NotYetValid` 107, `LifetimeTooLong`
108, `HopLimitExceeded` 109, `HopCountInflated` 110, `Replay` 111, `NoRoute`
112, `UnexpectedArrival` 113, `ConfidentialityExceedsSource` 114,
`ConfidentialityExceedsDestination` 115, `IntegrityExceedsSource` 116,
`IntegrityBelowFloor` 117, `CompartmentNotPermitted` 118,
`EncryptionRequired` 119, `SealedToWrongRecipient` 120, `PayloadTooLarge`
121, `RateLimited` 122, `Overloaded` 123.

Names and codes never change meaning once released; new ones are appended.

## 10. CCSDS Space Packet framing

An envelope MAY be carried as the user data of CCSDS Space Packets (CCSDS
133.0-B-2): packet version `000`, the 11-bit APID (0–2046; 2047 is the idle
APID and carries no user data), a 14-bit sequence count incremented modulo
16384, and the packet data length field equal to the data octets minus one
(1–65536 octets). An envelope larger than the mission's packet data size is
segmented with the sequence flags first (`01`), continuation (`00`) and last
(`10`); a whole envelope in one packet uses `11`. Receivers MUST discard a
partial message on a sequence-count gap, an out-of-order segment, or a size
overrun. This framing provides no security of its own; the envelope does.
Link-layer protection (CCSDS SDLS) is complementary.

## 11. Conformance

An implementation conforms to version 1 when, for the features it implements,
it produces the expected result for every record in:

| File | Feature |
|---|---|
| `cbor.rsp` | the deterministic CBOR profile (required for everything else) |
| `label.rsp` | labels |
| `ccsds.rsp` | Space Packets |
| `envelope.rsp` | decoding, verification, opening (with `keyring.pub`, `test-secrets.txt`) |
| `routing.rsp` | router decisions (with `routing-policy.ndb`, `keyring.pub`) |

The format is NIST CAVP `.rsp`: `#` comments, `[section]` headers,
`name = value` fields, blank lines between records. The Rust reference, the C,
Go, Swift and Java bindings, and the OpenSSL cross-check script all run them;
see [INTEROP.md](INTEROP.md). `test-secrets.txt` holds published test keys
that MUST NOT be used for anything else.

## 12. Security considerations

* **Metadata is visible.** The header (source, destination, label, size,
  times) travels in clear so routers can decide without decrypting. Where
  traffic analysis matters, protect links as well (TLS 1.3, MACsec, CCSDS
  SDLS) and pad payloads.
* **No forward secrecy for sealed payloads.** Sealing is to the recipient's
  static ML-KEM key; anyone who later obtains that decapsulation key can open
  past payloads sealed to it. Rotate ML-KEM keys on a schedule that matches
  the data's sensitivity lifetime (OPERATIONS.md).
* **Replay protection is per router** and lasts until expiry plus skew.
  Destinations SHOULD also keep a replay cache; applications needing
  exactly-once semantics must add their own.
* **Clocks.** Freshness depends on router clocks within `skew`. Where clocks
  are not trustworthy (some space segments), use generous lifetimes and rely
  on the replay cache.
* **Audit truncation.** The hash chain detects edits, insertions, deletions
  and reordering, but not removal of the newest lines. Export chain heads to
  storage the router cannot rewrite.
* **Resource exhaustion.** Inputs are bounded (section 3), routes cap sizes,
  sources are rate-limited, and a full replay cache refuses (`Overloaded`)
  rather than forgets.
* **Classified information.** Labels implement an information-flow policy;
  they do not make a system accredited to carry classified information, which
  requires an assessed cross-domain solution. See
  [compliance/FIPS-199-CNSSI-1253.md](compliance/FIPS-199-CNSSI-1253.md).
* **Implementation.** The reference library has no `unsafe` code outside the
  C ABI crate; the cryptographic module is AWS-LC (FIPS 140-3 module
  available). See [THREAT-MODEL.md](THREAT-MODEL.md).

## 13. Extension and versioning

* A new wire format gets a new `version`; decoders reject versions they do
  not implement (`Version`), checked before anything else.
* A new algorithm set gets a new `suite` number. Hybrid suites (for example
  ML-KEM-1024 with ECDH P-384) are candidates; see [ROADMAP.md](ROADMAP.md).
* Header keys 13 and above, unprotected keys 2 and above, error codes and
  reason codes not listed here are reserved.

## 14. References

Normative: RFC 2119, RFC 8174 (key words); RFC 8949 (CBOR); RFC 8610 (CDDL);
RFC 3629 (UTF-8); RFC 6838 (media types); RFC 9562 (UUIDs); RFC 5869 (HKDF);
FIPS 180-4, FIPS 197, FIPS 199, FIPS 203, FIPS 204; NIST SP 800-38D,
SP 800-56C Rev. 2; CCSDS 133.0-B-2 (Space Packet Protocol); IEEE 754-2019.

Informative: NSA CNSA 2.0; NIST SP 800-53 Rev. 5; CNSSI No. 1253; CCSDS
355.0-B (SDLS); CCSDS 734.20-O-1 / RFC 9171 (Bundle Protocol); RFC 9052
(COSE, whose `Sig_structure` idea section 7.3 follows); NIST CAVP (vector
file layout).
