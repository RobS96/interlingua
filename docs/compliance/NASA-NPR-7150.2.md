# NASA software engineering and assurance requirements

How a NASA project, or a project held to NASA practice, can use interlingua
and the evidence this repository provides toward NPR 7150.2D (*NASA Software
Engineering Requirements*) and NASA-STD-8739.8B (*Software Assurance and
Software Safety Standard*). interlingua is not NASA software and has not been
classified, assessed or approved by NASA ([DISCLAIMER.md](../../DISCLAIMER.md)).

## Software classification

NPR 7150.2D assigns each project's software a class (A for human-rated space
flight software through F for general-purpose business software), and the
class determines which requirements apply and how rigorously. A project that
embeds interlingua classifies **its own** software, with interlingua as an
open-source component. Requirements for flight classes (for example modified
condition / decision coverage for safety-critical code) are the embedding
project's to meet; the coverage, tests and analysis below are inputs to that,
not a substitute for it.

## Mapping by topic

Requirement identifiers are from NPR 7150.2D (March 2022). Confirm them
against the current revision on NODIS before relying on them.

| Topic | NPR 7150.2D | What this repository provides |
|---|---|---|
| Use of open-source and reused software | SWE-027 | licences (MIT OR Apache-2.0), a CycloneDX SBOM per release, provenance, dependency governance (cargo-deny, cargo-vet), a known-issue channel (SECURITY.md) |
| Electronic access to source code | SWE-042 | public repository, signed history, tagged releases |
| Unit testing with recorded results | SWE-062 | unit and conformance tests on every change; results in CI logs |
| Static analysis | SWE-135 | clippy at `-D warnings`, CodeQL on publication, zizmor for workflows |
| Evaluating software for security risks | SWE-156 | [THREAT-MODEL.md](../THREAT-MODEL.md) with STRIDE analysis and residual risks |
| Protection against unauthorized access for systems with communications | SWE-157 | signed envelopes, key-to-domain binding, label-based routing, sealing ([SPECIFICATION.md](../SPECIFICATION.md)) |
| Verifying and validating security mitigations | SWE-159 | each mitigation in the threat model points to a conformance vector or test |
| Secure coding standard verified by static analysis | SWE-185 | Rust with `forbid(unsafe_code)` and enforced lint set; `unsafe` confined and justified |
| Regression testing | SWE-191 | the full suite and all binding vectors run on every change |
| Secure coding practices | SWE-207 | [CONTRIBUTING.md](../../CONTRIBUTING.md), memory-safety roadmap |
| Detection of adversarial actions | SWE-210 | every rejection is an audit record with its reason; monitoring guidance in OPERATIONS.md |

## Software assurance (NASA-STD-8739.8B)

| Assurance activity | Evidence here |
|---|---|
| Independent analysis of requirements and design | specification, ADRs and threat model are separate from code and reviewable on their own |
| Code quality and security analysis | static analysis, fuzzing, sanitizers, dependency gates |
| Test witnessing and results | CI runs are public and reproducible with `make`; vectors are language-neutral |
| Configuration management | Git history with signed commits and tags; release provenance |
| Cybersecurity of the command link | end-to-end signatures and sealing on telecommands; see also NASA-STD-1006A, *Space System Protection Standard*, which addresses command-link protection at the mission level |

## Fit with NASA flight software frameworks

* **core Flight System (cFS)** and **F´ (F Prime)** applications are written
  in C and C++: link the static C library and call the C ABI from the app;
  carry envelopes as the user data of CCSDS Space Packets (cFS messages
  already use the CCSDS primary header).
* The library allocates per call and holds no global state except router
  handles; flight projects with static-allocation rules should wrap calls at
  initialization or use the CLI-equivalent at the ground segment only, until
  an allocation-free profile exists ([ROADMAP.md](../ROADMAP.md)).
