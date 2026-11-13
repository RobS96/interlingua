# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Wire-format
changes also bump the format `version` (docs/SPECIFICATION.md section 13).

## [Unreleased]

## [0.1.0] - not yet released

### Added

- Wire format version 1 and suite IL1-CNSA2: deterministic CBOR envelopes,
  ML-DSA-87 signatures, ML-KEM-1024 + HKDF-SHA-384 + AES-256-GCM sealing,
  FIPS 199 labels with compartments ([specification](docs/SPECIFICATION.md),
  [CDDL](spec/interlingua.cddl)).
- Strict deterministic CBOR codec (RFC 8949 section 4.2.1, enforced on decode).
- Label-based router: 24 ordered checks (Bell–LaPadula, Biba, sealing,
  freshness, replay, rate limits), deterministic shortest-path forwarding,
  SHA-384 hash-chained audit trail.
- Plan 9 ndb-style policy language ([POLICY.md](docs/POLICY.md)).
- CCSDS 133.0-B-2 Space Packet framing with segmentation and reassembly.
- C ABI (`bindings/c/include/interlingua.h`) and bindings for C, Swift
  (macOS, iOS), Go (cgo) and Java (JDK 22+ FFM).
- `il` command line: keys, seal, open, verify, inspect, route, audit-verify,
  CBOR diagnostics, CCSDS framing, conformance vectors.
- Conformance vectors (CBOR, labels, CCSDS, envelopes, routing) run by every
  binding, plus independent cross-checks with Apple CryptoKit, Go's standard
  library, the JDK and OpenSSL.
- Optional build against the AWS-LC FIPS 140-3 module (`--features fips`).
- Compliance mappings, threat model, architecture description, ADRs, CI with
  SHA-pinned actions, fuzzing, SBOMs and build provenance.
