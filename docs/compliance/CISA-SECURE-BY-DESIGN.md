# CISA Secure by Design

CISA's Secure by Design guidance (with NSA, FBI and international partners)
asks producers to own customer security outcomes, embrace radical
transparency, and lead from the top. The Secure by Design Pledge (May 2024)
sets seven goals. This page records where interlingua stands on each, and on
the *Product Security Bad Practices* list. interlingua has not signed the
pledge; the pledge is for organisations. This is a self-assessment.

## The seven pledge goals

| Goal | Status in interlingua |
|---|---|
| 1. Multi-factor authentication | Not applicable to a library with no user accounts. Anyone with write access to the repository must use phishing-resistant MFA (security keys or passkeys) on GitHub |
| 2. Default passwords | None exist. No default keys either: keys are generated per domain; the published test keys are named as such and isolated in `spec/vectors/` |
| 3. Reducing entire classes of vulnerability | Memory safety (Rust, `forbid(unsafe_code)`); parser differentials (strict canonical CBOR); injection (no shell, no string-built commands; audit fields sanitized); algorithm downgrade (no negotiation) |
| 4. Security patches | Dependabot with security updates undelayed; releases from CI only; patch releases for any security fix |
| 5. Vulnerability disclosure policy | [SECURITY.md](../../SECURITY.md): private reporting, timelines, safe harbour for good-faith research |
| 6. CVEs | Confirmed vulnerabilities get GitHub Security Advisories with CVE identifiers and CWE classifications |
| 7. Evidence of intrusions | Every routing decision is a hash-chained audit record, including every rejection with its reason; monitoring guidance in [OPERATIONS.md](../OPERATIONS.md#6-monitoring) |

## Principles

* **Own the security outcome.** Secure defaults (sealing from `moderate`,
  deny-by-default policy, fail closed), and hardening that needs no
  configuration: strict decoding, bounds, rate limits.
* **Radical transparency.** Normative specification, threat model with
  residual risks, this compliance folder, SBOMs and provenance on releases,
  and published test vectors anyone can run.
* **Lead from the top.** Security is a merge requirement, not a review
  suggestion: [CONTRIBUTING.md](../../CONTRIBUTING.md) and the PR template.

## Product Security Bad Practices: checklist

| Bad practice | interlingua |
|---|---|
| New product in a memory-unsafe language | Avoided: Rust; see [MEMORY-SAFETY-ROADMAP.md](../MEMORY-SAFETY-ROADMAP.md) for the one C/assembly component (the validated crypto module) |
| No published memory-safety roadmap | Published |
| User input in SQL or OS commands | No SQL, no shell, no command construction in the product |
| Default passwords | None |
| Known exploited vulnerabilities shipped | Dependency advisories gate CI (cargo-deny) |
| Open-source dependencies with known exploitable vulnerabilities | Same gate, plus Dependabot and dependency review on pull requests |
| No capability to gather evidence of intrusions | Hash-chained audit trail for every decision |
| No vulnerability disclosure policy | SECURITY.md |
| CVEs without CWE | Advisories carry CWE identifiers |
