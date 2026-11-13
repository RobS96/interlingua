# Memory-safety roadmap

CISA, NSA, the FBI and international partners ask software producers to
publish a memory-safety roadmap (*The Case for Memory Safe Roadmaps*, December
2023; CISA and FBI *Product Security Bad Practices*, which sets the
expectation that producers of products written in memory-unsafe languages
publish one; NSA *Software Memory Safety*, November 2022; CISA and NSA *Memory
Safe Languages: Reducing Vulnerabilities in Modern Software Development*,
June 2025). This is interlingua's.

## Where the code stands today

| Component | Language | Memory safety |
|---|---|---|
| Library (`crates/interlingua`) | Rust | `#![forbid(unsafe_code)]`: the compiler rejects any `unsafe` |
| CLI (`crates/interlingua-cli`) | Rust | `#![forbid(unsafe_code)]` |
| C ABI (`crates/interlingua-ffi`) | Rust | `unsafe` only to convert C pointers; each block carries a `SAFETY:` justification (`clippy::undocumented_unsafe_blocks` is an error); every pointer and length is checked; panics are caught |
| Bindings | Swift, Go, Java | memory-safe languages calling the C ABI; C is only the conformance runner, built under AddressSanitizer + UBSan |
| Cryptographic module | AWS-LC: C and assembly | see below |
| Build tools (cc, cmake crates) | Rust | build time only |

New product code is written in memory-safe languages only; this is a
project rule, not an aspiration ([CONTRIBUTING.md](../CONTRIBUTING.md)).

## The one memory-unsafe component: the cryptographic module

AWS-LC is written in C and assembly. It is kept because, for this purpose,
a cryptographic module that is FIPS 140-3 validated, constant-time,
continuously fuzzed and partly formally verified (AWS-LC's verified
implementations of several primitives) outweighs a memory-safe module that
is not validated. The risk is contained:

* one module only (`deny.toml` bans OpenSSL, ring and native-tls from the
  graph), exact-version pinned and bumped only by reviewed pull requests;
* called only through aws-lc-rs's safe Rust API;
* inputs reach it only after strict decoding and length checks;
* independent implementations (Apple CryptoKit, Go, the JDK, OpenSSL) check
  its results in CI, so a defect that changes outputs is visible.

## Milestones

| When | Milestone |
|---|---|
| Done (0.1) | Memory-safe core and CLI; `unsafe` confined to the ABI crate; fuzzing and sanitizers in CI |
| 0.2 | Kani or similar bounded proofs that the CBOR decoder never panics and never reads out of bounds for inputs up to a fixed size |
| 0.3 | A pure-Rust cryptographic backend behind a feature flag, for targets where a validated module is not required, kept in lockstep by the same vectors |
| When a validated memory-safe module exists | Make it the default backend; keep AWS-LC as an option |
| Each release | Count `unsafe` blocks (target: no growth), review every one, and publish the count in the changelog |

## How progress is measured

* `unsafe` blocks: counted in `crates/interlingua-ffi` (all are pointer
  conversions at the boundary).
* Memory-safety defects reported against interlingua's own code: tracked as
  security advisories (none at the time of writing).
* Fuzzing hours per release and sanitizer results: from CI.
