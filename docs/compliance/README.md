# Compliance posture

**What this folder is.** Maps from public standards to what interlingua
implements, where in the code, and what evidence shows it works, so that a
system owner or assessor can start from facts rather than from claims.

**What it is not.** interlingua is a software *component*. Standards such as
NIST SP 800-53 apply to *systems* and organisations; FIPS 140-3 applies to
cryptographic *modules*. No assessment, certification or authorization has
been performed for interlingua, and none is implied ([DISCLAIMER.md](../../DISCLAIMER.md)).

## Shared responsibility

| Responsibility | interlingua | The operator / system owner |
|---|---|---|
| Message authenticity and integrity | ML-DSA-87 signatures, strict canonical decoding, keyring binding | distribute keyrings over authenticated channels; protect signing keys |
| Payload confidentiality | ML-KEM-1024 + AES-256-GCM end to end | key storage (HSM / keystore), rotation, destruction |
| Information flow | label-based router (Bell–LaPadula, Biba, compartments, sealing rules) | write and review the policy; categorize data correctly |
| Audit | one hash-chained record per decision | ship, retain, anchor and review the records |
| Availability | bounded decoders, rate limits, fail-closed state | capacity, redundancy, link protection |
| Cryptographic module validation | builds against AWS-LC's FIPS module | choose the validated version and operational environment; run in approved mode |
| Secure development | the controls in NIST-SSDF.md, CI evidence | integrate the component into their own SDLC and assessments |

## Index

| Document | Standard |
|---|---|
| [NIST-SP-800-53r5.md](NIST-SP-800-53r5.md) | NIST SP 800-53 Rev. 5 security controls |
| [NIST-SSDF.md](NIST-SSDF.md) | NIST SP 800-218 Secure Software Development Framework |
| [CISA-SECURE-BY-DESIGN.md](CISA-SECURE-BY-DESIGN.md) | CISA Secure by Design principles and pledge goals; Product Security Bad Practices |
| [CNSA-2.0.md](CNSA-2.0.md) | NSA Commercial National Security Algorithm Suite 2.0 |
| [FIPS-140-3.md](FIPS-140-3.md) | Cryptographic module validation |
| [FIPS-199-CNSSI-1253.md](FIPS-199-CNSSI-1253.md) | Security categorization (the C-I-A triad) |
| [NASA-NPR-7150.2.md](NASA-NPR-7150.2.md) | NASA software engineering and assurance requirements |
| [CCSDS.md](CCSDS.md) | Space data systems standards |
| [IEEE.md](IEEE.md) | IEEE and ISO/IEC/IEEE engineering standards |
| [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md) | SLSA, SBOM, OpenSSF, dependency governance |
| [../MEMORY-SAFETY-ROADMAP.md](../MEMORY-SAFETY-ROADMAP.md) | CISA / NSA memory-safety guidance |

## Evidence

| Evidence | Where |
|---|---|
| Specification and schema | [SPECIFICATION.md](../SPECIFICATION.md), [interlingua.cddl](../../spec/interlingua.cddl) |
| Conformance vectors and results per language | [spec/vectors/](../../spec/vectors), [README](../../README.md#proven-interoperability), CI logs |
| Threat model and residual risks | [THREAT-MODEL.md](../THREAT-MODEL.md) |
| Architecture and design decisions | [ARCHITECTURE.md](../ARCHITECTURE.md), [adr/](../adr/) |
| Static analysis, tests, fuzzing, sanitizers | `.github/workflows/ci.yml`, `fuzz.yml` |
| Dependency gates | `deny.toml`, `supply-chain/`, Dependabot |
| Release integrity | `.github/workflows/release.yml` (signed tags, SBOMs, provenance) |

Standards are revised. Each document names the revision it maps; check for
newer revisions before relying on a mapping.
