**What does this change?**

**Why?**

**Checklist**

- [ ] `make rust` passes (fmt, clippy `-D warnings`, tests)
- [ ] Bindings I touched pass locally (`make c`, `make go`, `make swift`, `make java`, `make openssl`)
- [ ] A behaviour change comes with conformance vectors in `spec/vectors/` (every binding runs them)
- [ ] Wire-format, crypto or router changes update `docs/SPECIFICATION.md` and, if a trust decision moves, `docs/THREAT-MODEL.md`
- [ ] New dependencies pass `cargo deny check` and `cargo vet check` (with an audit or a reasoned exemption)
- [ ] `CHANGELOG.md` updated under *Unreleased* if user-visible
- [ ] Commits are signed
