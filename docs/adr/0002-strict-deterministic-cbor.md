# ADR 0002: Strict deterministic CBOR as the canonical form

**Status:** accepted · 2026-11-13

## Context
Signatures cover bytes. If two encodings of the same value are both
accepted, two implementations can disagree about what was signed, and an
attacker can exploit the difference (a parser differential).

## Decision
Use CBOR (RFC 8949) with Core Deterministic Encoding (§4.2.1), enforced on
**decode** as well as encode: reject non-shortest integers, indefinite
lengths, tags, `undefined`, non-preferred floats, non-canonical NaN,
unsorted or duplicate map keys, invalid UTF-8; bound depth, items and size.
Verify signatures over the bytes received.

## Consequences
* `encode(decode(x)) == x` for every accepted input (fuzzed).
* Some valid CBOR from other tools is refused; producers must emit
  deterministic CBOR, which most libraries can.
* Binary and compact: a sealed telecommand is ~6.5 KB, dominated by the
  4627-byte ML-DSA-87 signature and the 1568-byte ML-KEM ciphertext.
