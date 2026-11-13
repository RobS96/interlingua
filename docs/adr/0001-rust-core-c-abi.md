# ADR 0001: One Rust core behind a C ABI

**Status:** accepted · 2026-11-13

## Context
Five languages (Rust, C, Swift, Go, Java) must produce and accept identical
bytes and make identical routing decisions. Re-implementing the format in
each language multiplies the code that must stay in agreement and the places
a security bug can hide.

## Decision
Implement the format, cryptography, policy and router once, in Rust with
`#![forbid(unsafe_code)]`. Expose it through one C ABI (`interlingua.h`),
the only interface every language can call natively. Bindings are thin,
idiomatic wrappers; none re-implements behaviour.

## Consequences
* Agreement between languages reduces to agreement of thin wrappers, which
  the shared vectors check.
* `unsafe` exists only in the ABI crate, at pointer conversion.
* Independent implementations are still needed to check the *specification*
  (not just the code): see ADR 0009 and the cross-checks.
* Shipping requires a native library per platform (static or shared).
