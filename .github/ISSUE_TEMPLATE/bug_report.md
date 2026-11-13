---
name: Bug report
about: Something behaves differently from docs/SPECIFICATION.md or the vectors
labels: bug
---

**What happened, and what did you expect?**

**Smallest input that shows it**
Hex of the envelope / CBOR / packet, the policy lines, and the exact command
or binding call. Never paste real keys: use the published test keys in
`spec/vectors/test-secrets.txt` or freshly generated ones.

**Where**
- `il version` (or the binding's version):
- Language binding and version (Rust / C / Swift / Go / Java):
- OS and architecture:

**A conformance vector that should exist**
If you can, write the record (`.rsp` format) the fix should make pass.
