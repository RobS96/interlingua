# NIST SP 800-218: Secure Software Development Framework

Mapping to the practices of SSDF version 1.1 (February 2022). The SSDF is the
basis of the U.S. federal secure software development attestation; this
document records how this project performs each practice so that a producer
or consumer can reference it. Check for later revisions of SP 800-218.

## PO: Prepare the Organization

| Practice | How this project does it |
|---|---|
| PO.1 Define security requirements | Security properties are normative in [SPECIFICATION.md](../SPECIFICATION.md) and [THREAT-MODEL.md](../THREAT-MODEL.md); conformance vectors make them testable |
| PO.2 Roles and responsibilities | [GOVERNANCE.md](../../GOVERNANCE.md), CODEOWNERS |
| PO.3 Supporting toolchains | Pinned Rust toolchain policy, SHA-pinned actions, hash-pinned CI tools, Dependabot |
| PO.4 Criteria for security checks | CI gates: fmt, clippy `-D warnings`, tests, vectors in every binding, cargo-deny, cargo-vet, zizmor, MSRV, fuzzing |
| PO.5 Secure development environments | GitHub-hosted ephemeral runners; read-only default tokens; `persist-credentials: false`; no secrets in CI except the release job's OIDC token |

## PS: Protect the Software

| Practice | How |
|---|---|
| PS.1 Protect all forms of code | Signed commits required on `main`; pull requests only; force-push and deletion blocked |
| PS.2 Verify release integrity | SHA256SUMS, Sigstore build-provenance attestation, signed annotated tags checked by the release job |
| PS.3 Archive and protect releases | GitHub releases with SBOMs and provenance bundles attached |

## PW: Produce Well-Secured Software

| Practice | How |
|---|---|
| PW.1 Design to meet requirements and mitigate risks | Threat model with STRIDE table; architecture description; deny-by-default design |
| PW.2 Review the design | ADRs for each design decision; spec-first changes (CONTRIBUTING.md) |
| PW.4 Reuse well-secured software | One validated cryptographic module (AWS-LC) instead of custom cryptography |
| PW.5 Secure coding practices | Memory-safe Rust; `forbid(unsafe_code)`; workspace lints against panics; strict input validation |
| PW.6 Secure build configuration | Release profile with overflow checks and LTO; reproducible inputs (`--locked`); deployment targets pinned |
| PW.7 Review and analyze code | Code review on every pull request; clippy; CodeQL on publication |
| PW.8 Test executable code | Unit, conformance, property (100 000 inputs), fuzz, ASan/UBSan, cross-implementation tests |
| PW.9 Secure defaults | Sealing mandatory from `moderate`; deny-by-default policy; keys written `0600` and never overwritten; no default keys or credentials |

## RV: Respond to Vulnerabilities

| Practice | How |
|---|---|
| RV.1 Identify vulnerabilities continuously | RustSec advisories (cargo-deny), Dependabot alerts, OpenSSF Scorecard, weekly fuzzing |
| RV.2 Assess, prioritize, remediate | [SECURITY.md](../../SECURITY.md) timelines; CVSS v4.0; advisories with CVE identifiers |
| RV.3 Analyze root causes | Each fix adds a conformance vector or test that would have caught it; post-incident notes in the advisory |
