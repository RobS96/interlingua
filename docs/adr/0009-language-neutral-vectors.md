# ADR 0009: Language-neutral conformance vectors with stated expectations

**Status:** accepted · 2026-11-13

## Context
Agreement between implementations must be checked, not assumed, and the
check must not simply record what the current code happens to do.

## Decision
Vectors use the NIST CAVP `.rsp` layout (trivial to parse in any language).
Static vectors are hand-written from their sources (RFC 8949 Appendix A …).
Generated vectors take their *expected* results from scenario tables in the
generator, never from running the code under test. Every binding runs every
suite; independent implementations check the cryptography.

## Consequences
* A behaviour change shows up as failing vectors, which must be changed
  deliberately and reviewed.
* Test keys are published and must never be used for real traffic.
