# Design principles and heritage

interlingua borrows deliberately from engineering traditions that solved
"many systems, one language" before. None of the organisations below are
involved in this project ([DISCLAIMER.md](../DISCLAIMER.md)); their published
ideas are.

## From Bell Labs: Unix, C, UTF-8, Plan 9

| Idea | Where it came from | How interlingua uses it |
|---|---|---|
| Small tools that compose through text streams | the Unix philosophy, usually summarised from Doug McIlroy as "write programs that do one thing and do it well … that work together … that handle text streams" | every `il` subcommand is a filter (stdin to stdout, diagnostics on stderr, meaningful exit status); audit records, key bundles and policies are line-oriented text that `grep` and `awk` can read |
| A portable systems language as the common interface | C (Dennis Ritchie, early 1970s) | the C ABI is the one seam every language binds to |
| One text encoding for every script | UTF-8, designed by Ken Thompson and Rob Pike in 1992 for Plan 9 | all text is UTF-8; identifiers are its ASCII subset so equality is bytewise |
| Configuration as attribute=value records | Plan 9's `ndb(6)` network database | the policy language ([POLICY.md](POLICY.md)) |
| Error-detecting codes and channel capacity | Shannon (1948), Hamming (1950) | not reimplemented: integrity is cryptographic (ML-DSA-87, AES-GCM tags); link-level coding stays with the CCSDS layer below |
| Build descriptions as dependency rules | `make` (Stuart Feldman, 1976) | a POSIX `Makefile` drives every binding's proof |

Go, one of the bindings, was created at Google by Robert Griesemer, Rob Pike
and Ken Thompson; the last two came from the Bell Labs Unix and Plan 9 groups.

## From Java: one runtime, many platforms; and now native access

Java's promise was code that runs unchanged wherever the JVM does. The
binding uses the **Foreign Function & Memory API** (final in JDK 22, JEP 454)
instead of JNI: no C glue to compile, memory confined to arenas, and native
access that must be explicitly enabled. The JDK's own post-quantum
implementations (ML-KEM, JEP 496; ML-DSA, JEP 497) and its Key Derivation
Function API (JEP 510) are used in CI as independent checks of the
cryptography.

## From Apple platforms: native cryptography on the device

On macOS and iOS 26, CryptoKit provides ML-DSA-87 and ML-KEM-1024. The Swift
binding uses interlingua for the format and routing, and the conformance
runner uses CryptoKit to check, independently, that the published keys,
signatures, key derivation and encryption are what FIPS 203 and 204 say they
are, and to build a complete envelope from scratch that the reference accepts.

## From flight software: predictability first

NASA's core Flight System and JPL's F´ show what flight code needs: bounded
resources, no surprises at run time, C interfaces, CCSDS packets. Hence: no
clock, file or network access in the library; explicit limits on every
decoder; integer-only arithmetic in the router; deterministic path choice; a
static C library; CCSDS Space Packet framing.

## From the security community: the CIA triad and its models

*Confidentiality, integrity, availability* (the "CIA triad", the basis of
FIPS 199 categorisation) organise the label, and three classic models enforce
it: Bell–LaPadula for confidentiality (no write-down), Biba for integrity (no
write-up of lower-integrity data), and rate limits with bounded,
fail-closed state for availability.

## Principles in one list

1. **One canonical form**, strictly enforced on input.
2. **One cryptographic module**, one suite per version, no negotiation.
3. **Deny by default**; every allowed flow is a line someone can review.
4. **Fail closed**, change state last.
5. **No hidden inputs**: time, bytes and policy are parameters.
6. **Text where humans read, CBOR where machines sign.**
7. **Prove, don't claim**: vectors in every language, independent
   cross-checks, fuzzing, sanitizers.
8. **Write it down**: specification, ADRs, threat model, compliance mapping.
