# ADR 0004: Hop count outside the signature, bounded by a signed maximum

**Status:** accepted · 2026-11-13

## Context
Routers must decrement a hop count, but they cannot re-sign (they do not
hold the source's key) and must not be able to alter anything else.

## Decision
The envelope has an unprotected map holding only `{1: hops}`. The signed
header carries `max_hops`; routers reject `hops > max_hops`. Every other byte
is covered by the source's signature and forwarded unchanged.

## Consequences
* A malicious relay can only spend hops faster (cause an earlier drop), never
  extend a message's reach.
* Unknown unprotected keys are rejected, so the bucket cannot become a
  side channel for unauthenticated data.
