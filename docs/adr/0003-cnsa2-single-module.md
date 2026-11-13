# ADR 0003: CNSA 2.0 suite from one module, no negotiation

**Status:** accepted · 2026-11-13

## Context
Messages may need to stay confidential and authentic for decades
(harvest-now-decrypt-later). Algorithm negotiation enables downgrade
attacks. Multiple crypto libraries multiply the validation and patching
surface.

## Decision
Suite 1 (IL1-CNSA2): ML-DSA-87, ML-KEM-1024, HKDF-SHA-384, AES-256-GCM,
SHA-384, exactly; no negotiation. All primitives come from AWS-LC (via
aws-lc-rs), pinned exactly, with a build option for its FIPS 140-3 module.
`deny.toml` bans other crypto and TLS stacks.

## Consequences
* Large signatures and ciphertexts (acceptable for command and control,
  heavy for high-rate telemetry; batch where needed).
* A future suite is a new number in the header, never a negotiation.
* AWS-LC is C and assembly: the one memory-unsafe component, accepted for
  validation (MEMORY-SAFETY-ROADMAP.md).
