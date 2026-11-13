# IEEE and ISO/IEC/IEEE engineering standards

Engineering standards whose practices or structure this project follows.
"Follows" means the relevant practice is applied and visible in the
repository; no conformity assessment has been performed.

| Standard | How it is applied |
|---|---|
| **IEEE 754-2019**, floating-point arithmetic | Headers carry no floats. For payload data, deterministic CBOR fixes one encoding per value: shortest exact binary16/32/64 width, `-0.0` preserved, one canonical NaN; vectors pin subnormals, infinities and NaN payloads to the bit ([INTEROP.md §4](../INTEROP.md#4-numbers-text-and-time)) |
| **IEEE Std 1003.1-2024** (POSIX.1) | The CLI behaves as a POSIX filter (stdin, stdout, stderr, exit status); scripts are POSIX `sh`; the Makefile uses POSIX constructs plus documented GNU make conveniences |
| **ISO/IEC/IEEE 42010:2022**, architecture description | [ARCHITECTURE.md](../ARCHITECTURE.md) identifies stakeholders, concerns, and one view per concern |
| **ISO/IEC/IEEE 12207:2017**, software life cycle processes | Requirements (specification), architecture, implementation, verification (vectors, CI), configuration management (Git, signed tags), maintenance (Dependabot, advisories) are each defined and traceable |
| **ISO/IEC/IEEE 29148:2018**, requirements engineering | Normative requirements use BCP 14 key words and each is testable through the vectors |
| **ISO/IEC/IEEE 29119**, software testing | Test levels (unit, conformance, property, fuzz, cross-implementation, end-to-end example), test basis (the specification), and recorded results (CI) |
| **IEEE Std 1012**, verification and validation | Verification against the specification in every language; validation through independent implementations building and checking real envelopes |
| **IEEE Std 730-2014**, software quality assurance | Quality gates are automated in CI and listed in CONTRIBUTING.md |
| **IEEE Std 828-2012**, configuration management | Versioned specification, Semantic Versioning, CHANGELOG, locked dependencies, signed releases |
| **IEEE 2675-2021**, DevOps | Continuous integration with security gates, reproducible builds from locked inputs, release automation with provenance |
| **IEEE 1588-2019** (PTP) | Recommended for synchronizing router clocks within the policy's clock skew ([OPERATIONS.md §4](../OPERATIONS.md#4-running-a-router)) |
| **IEEE 802.1AE** (MACsec) | Recommended link-layer protection between router hosts on Ethernet, since headers are visible by design |
