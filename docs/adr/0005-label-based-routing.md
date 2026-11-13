# ADR 0005: Label-based routing with Bell–LaPadula and Biba, deny by default

**Status:** accepted · 2026-11-13

## Context
Domains differ in clearance and integrity. Edge-only (firewall-style) checks
leave relays trusted and make policy hard to audit.

## Decision
Every message carries a FIPS 199 label with compartments. Every router, at
every hop, applies a fixed, ordered procedure: authenticity, freshness,
source may originate, destination cleared (Bell–LaPadula), integrity floor
(Biba), compartments, sealing rules, a permitted path through permitted
relays, replay, rate. Only explicitly declared edges exist.

## Consequences
* Decisions are explainable: every rejection has one named reason.
* The order is part of the specification, so every implementation reports
  the same reason (vectors check it).
* Labels are policy, not accreditation (FIPS-199-CNSSI-1253.md).
