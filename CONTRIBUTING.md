# Contributing

Thank you for considering a contribution. Two rules shape everything here:

1. **The vectors are the contract.** A change in behaviour comes with records
   in `spec/vectors/`, and every language binding must pass them. If two
   implementations disagree, the specification and the vectors decide.
2. **Security decisions are written down.** Wire-format, cryptography and
   router changes update [docs/SPECIFICATION.md](docs/SPECIFICATION.md), and an
   architecture decision record in [docs/adr/](docs/adr/) when a design choice
   changes; anything that moves a trust boundary updates
   [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Layout

```
crates/interlingua/      library (no unsafe, no I/O, no clock)
crates/interlingua-ffi/  C ABI: the only crate allowed `unsafe`
crates/interlingua-cli/  `il` and the vector generator
bindings/{c,swift,go,java}/
spec/                    CDDL schema and conformance vectors
docs/                    specification, design, compliance, ADRs
```

## Setup

* Rust 1.88 or newer (the workspace `rust-version`, proven by CI's MSRV job)
  and a C compiler (AWS-LC is C and assembly). `--features fips` builds also
  need CMake and Go.
* Optional, per binding: Go 1.27+, Swift 6 (Xcode or the Swift toolchain),
  JDK 25, OpenSSL 3.5+.

## Before opening a pull request

```bash
make rust            # cargo fmt --check, clippy -D warnings, cargo test
make c go swift      # the bindings you can run locally
make vectors         # the CLI over spec/vectors
make supply          # when dependencies change: cargo deny + cargo vet
```

CI additionally builds the docs with warnings as errors, spell-checks with
typos, runs the Java binding on JDK 25, builds against the AWS-LC FIPS module,
checks the MSRV, fuzzes every target, and lints the workflows with zizmor.

## Changing the vectors

Static vectors (`cbor.rsp`, `label.rsp`, `ccsds.rsp`) are written by hand and
cite their source. `envelope.rsp` and `routing.rsp` are regenerated with
`il vectors generate spec/vectors`: the generator writes the *expected*
results from its scenario tables, never by running the code under test, so a
regression shows up as a failing check rather than a silently updated vector.
Review the diff of expectations, not of hex.

## Code style

* `cargo fmt`; clippy clean at `-D warnings` with the workspace lints
  (`unwrap_used`, `expect_used` and `panic` warn outside tests).
* No new dependency without a reason in the pull request, a `cargo vet`
  audit or reasoned exemption, and a licence on the `deny.toml` allow-list.
* Errors carry stable identifiers; never reuse or renumber one.
* Comments explain *why*; the code says *what*.

## Commits

Signed commits only (GitHub verifies them; the branch rules require it), one
logical change per commit, imperative subject line. Do not commit keys other
than the published test keys.

## Conduct

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies to every space of the project.
