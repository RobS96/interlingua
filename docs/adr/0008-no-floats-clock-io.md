# ADR 0008: No floats in headers; no clock, network or files in the core

**Status:** accepted · 2026-11-13

## Context
Floating-point formatting and rounding differ across languages; hidden
inputs (clocks, files, sockets) make decisions irreproducible and the
trusted base larger.

## Decision
Header fields are integers, byte strings, text and booleans only. The core
library takes time and bytes as parameters and performs no I/O.

## Consequences
* Every routing decision can be replayed exactly from its inputs (the
  vectors do this).
* Hosts own transport, persistence and time, and must supply trusted time.
