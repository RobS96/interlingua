# Supply-chain security

## Dependencies

* **Small**: 15 third-party crates on a given platform, most of them
  AWS-LC and its build tools. `cargo vet` sees 40 across all features and
  platforms.
* **Gated**: `cargo deny check` (RustSec advisories, yanked crates, a
  permissive licence allow-list, crates.io as the only source, and bans on a
  second crypto or TLS stack); `cargo vet check` (every crate audited or
  explicitly exempted); dependency review on every pull request.
* **Honest status**: seven published audit sets are imported (Mozilla,
  Google, Bytecode Alliance, ISRG, Zcash, Embark, Fermyon). They fully audit
  10 of the 40 crates; the other 30 remain *exemptions* in
  `supply-chain/config.toml`, chiefly AWS-LC (`aws-lc-rs`, `aws-lc-sys`,
  `aws-lc-fips-sys`) and its build tools, which no imported set covers.
  Converting those needs our own `cargo vet certify` audits.
* **Updated deliberately**: Dependabot groups minor and patch bumps weekly
  with a seven-day cooldown; security updates are not delayed. AWS-LC is
  pinned exactly, so the cryptographic module changes only through its own
  reviewed pull request.

## Build and CI

* GitHub Actions pinned to full commit SHAs, updated by Dependabot.
* Read-only default token; `persist-credentials: false` on every checkout;
  write permissions only in the release job.
* Workflows audited by zizmor (template injection, unpinned actions, cache
  poisoning, excessive permissions).
* CI tools installed from crates.io or PyPI at pinned versions, the PyPI
  wheels by SHA-256.
* No cache is restored for release builds; releases build from the locked
  tree only.

## Releases

| Artefact | Standard |
|---|---|
| Signed, annotated tag on `main`, checked by the release job | source integrity |
| SHA256SUMS per platform | download integrity |
| Build provenance attestation, attached as a Sigstore bundle | SLSA provenance: Build L2 (signed provenance from a hosted build platform); L3 needs build isolation beyond this workflow's design |
| CycloneDX SBOM per crate | the NTIA / CISA minimum elements: supplier, component, version, unique identifiers, dependency relationships, author, timestamp |
| BUILD-INFO.txt inside each archive | commit, toolchain, runner image, Cargo.lock digest |

Verify a download with `gh attestation verify <file> --repo RobS96/interlingua`.

## Repository

* Signed commits required on `main`; pull requests only; no force-push or
  deletion (branch rules, set at publication).
* OpenSSF Scorecard runs weekly and on every push to `main`.
* Secret scanning with push protection, private vulnerability reporting,
  CodeQL default setup, Dependabot alerts: enabled at publication
  ([ROADMAP.md](../ROADMAP.md)).
