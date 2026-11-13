# Security policy

## Supported versions

interlingua is pre-1.0; only the latest release receives security fixes.

| Version | Supported |
| ------- | --------- |
| latest  | ✅        |
| older   | ❌        |

## Reporting a vulnerability

Report security issues **privately** through
[GitHub private vulnerability reporting](https://github.com/RobS96/interlingua/security/advisories/new),
never in a public issue, pull request or discussion. Include what you found,
how to reproduce it (an input in hex is ideal; use the published test keys in
`spec/vectors/test-secrets.txt`, never real keys) and the version
(`il version`).

* **Acknowledgement** within 7 days.
* **Assessment** (severity using CVSS v4.0, affected versions) within 14 days.
* **Fix target**: 30 days for high and critical issues, 90 days otherwise,
  coordinated with you.
* **Disclosure**: a GitHub Security Advisory with a CVE identifier for any
  confirmed vulnerability in a release, crediting you unless you prefer
  otherwise. This follows coordinated vulnerability disclosure as described
  in ISO/IEC 29147 and CISA's guidance; we will not take legal action against
  good-faith research that follows this policy.

## In scope

Anything that breaks a property in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md), in particular:

- an envelope that any implementation accepts as authentic although it was
  not signed by a key bound to its source domain;
- a router that delivers or forwards a message its policy forbids, or that
  rejects one without an audit line;
- two encodings of one value that any decoder accepts (canonical-form break),
  or a disagreement between bindings on any conformance vector;
- recovery of a sealed payload without the recipient's decapsulation key;
- memory-safety bugs, panics or unbounded resource use on untrusted input,
  in the library or across the C ABI;
- audit-chain forgery that `il audit-verify` does not detect;
- weaknesses in the release pipeline (provenance, checksums, signed tags).

Out of scope: vulnerabilities in AWS-LC, the JDK, Go, Swift or OpenSSL
themselves (report them upstream; tell us if interlingua is affected), and
attacks that require control of the router host or its keys.

## How interlingua is hardened

`#![forbid(unsafe_code)]` outside the C ABI crate; strict deterministic CBOR
with bounds on depth, items and size; one cryptographic module (AWS-LC, FIPS
140-3 module available) with no algorithm negotiation; secrets zeroized on
drop; ML-KEM keys checked with the FIPS 203 hash check and a pairwise test;
fail-closed routing whose state changes only after every check passes; a
SHA-384 hash-chained audit trail; libFuzzer targets for every parser and the
router; property tests over 100 000 mutated inputs; AddressSanitizer and
UBSan on the C boundary; independent cryptographic cross-checks (Apple
CryptoKit, Go, the JDK, OpenSSL). Dependencies are gated by `cargo deny` and
`cargo vet`; GitHub Actions are pinned to commits with read-only default
tokens and audited by zizmor; releases come from signed tags with SLSA build
provenance and CycloneDX SBOMs.
