# Roadmap

Ordered by value; each item ships with specification text, vectors and CI.

## Next

1. **Publish** the repository with the GitHub settings the project's other
   public repositories use: rulesets requiring pull requests and signed
   commits, private vulnerability reporting, secret scanning with push
   protection, CodeQL default setup, Dependabot alerts, OpenSSF Best
   Practices registration.
2. **cargo-vet imports** of published audit sets (Mozilla, Google, Bytecode
   Alliance, ISRG, Zcash) to replace exemptions with audits.
3. **XCFramework** for iOS and macOS apps (arm64, arm64-simulator, x86_64),
   built in the release workflow.
4. **Maven Central** publication of the Java binding with the native library
   per platform, signed.

## Then

5. **DTN adapter**: carry envelopes as Bundle Protocol version 7 bundles
   (RFC 9171; CCSDS 734.20-O-1) with BPSec (RFC 9172) as the link-level
   complement, for delay-tolerant and interplanetary paths.
6. **Hybrid suite** (`suite = 2`): ML-KEM-1024 combined with ECDH P-384 and
   ML-DSA-87 with ECDSA P-384, for deployments whose policy requires hybrid
   during the post-quantum transition.
7. **Stateful hash-based signatures** (LMS/XMSS, SP 800-208) as a suite for
   firmware and software update envelopes, matching CNSA 2.0's guidance for
   code signing.
8. **Kani proofs** for the CBOR decoder and the router's bounds
   ([MEMORY-SAFETY-ROADMAP.md](MEMORY-SAFETY-ROADMAP.md)).
9. **Persistent replay cache** option for routers that restart often.
10. **Flight profile**: a `no_std` + `alloc`-bounded build of the codec,
    verification and CCSDS layers with caller-provided buffers, for flight
    software with static-allocation rules.
11. **Kotlin/Android** and **C++** header-only wrappers over the C ABI.

## Considered and not planned

* **Algorithm negotiation.** One suite per version keeps downgrade attacks
  impossible; a new suite is a new number, chosen by the sender and policy.
* **JSON wire format.** Text is used where people read (policies, audit,
  keys); signatures need one byte-exact form, which JSON does not have.
* **Accreditation claims.** The project documents controls and evidence; it
  will not describe itself as certified, accredited or approved by any body.
