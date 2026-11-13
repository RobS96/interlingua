# ADR 0007: SHA-384 hash-chained text audit records

**Status:** accepted · 2026-11-13

## Context
Audit records must show every decision, resist tampering, and be readable by
standard log tooling without a schema library.

## Decision
One line of `attr=value` tokens per decision; each line ends with
`prev=sha384:<previous hash> hash=sha384:<hash of this line>`. Values are
sanitized to single printable tokens.

## Consequences
* Edits, insertions, deletions and reordering are detected by
  `il audit-verify`; truncation needs an external anchor (OPERATIONS.md).
* Readable with `grep`/`awk`; no JSON escaping questions.
