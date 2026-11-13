# ADR 0006: A Plan 9 ndb-style policy language

**Status:** accepted · 2026-11-13

## Context
Policies are security-critical and reviewed by people. Formats with complex
grammars (YAML anchors, implicit typing) hide surprises; adding a TOML or
YAML parser adds dependencies to the core.

## Decision
One record per line, `attr=value` pairs, `#` comments, indented
continuations, as in Plan 9's `ndb(6)`. A small strict parser in the core
rejects unknown attributes, duplicates and every ambiguity with a line number.

## Consequences
* Diffs are line-based and readable; `grep` works on policies.
* The parser is in the core, so every binding gets identical semantics.
* Values cannot contain spaces (none need to).
