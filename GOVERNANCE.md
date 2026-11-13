# Governance

## Roles

* **Maintainer**: RobS96 (see `.github/CODEOWNERS`). Reviews and merges every
  change, cuts releases, triages security reports.
* **Contributors**: anyone who opens an issue or a pull request under
  [CONTRIBUTING.md](CONTRIBUTING.md) and the
  [Code of Conduct](CODE_OF_CONDUCT.md).

The project is maintained by one person today. To keep it from depending on
one person's memory, decisions are written down: design choices as ADRs in
[docs/adr/](docs/adr/), normative behaviour in the specification and the
conformance vectors, security posture in the threat model.

## How decisions are made

| Change | Needs |
|---|---|
| Bug fix, docs, tests | review + green CI |
| New feature, binding or dependency | an issue first, then review + green CI |
| Wire format, cryptography, router semantics | an ADR, specification and vectors in the same pull request, and a version or suite bump when existing envelopes would change meaning |
| Security fix | handled privately per [SECURITY.md](SECURITY.md); merged with the advisory |

`main` accepts changes only through pull requests with green required checks
and signed commits. Force-pushes and branch deletion of `main` are blocked.

## Releases

Semantic Versioning. A release is a signed, annotated tag `vX.Y.Z` on `main`;
the release workflow refuses anything else, builds per-platform archives,
attaches CycloneDX SBOMs and SHA256SUMS, and signs SLSA build provenance
with GitHub's Sigstore-backed attestations. [CHANGELOG.md](CHANGELOG.md)
records every user-visible change.

## Succession

If the maintainer becomes unavailable, the repository remains under the MIT
and Apache-2.0 licences; anyone may fork it. Because behaviour is fixed by
the specification and the vectors rather than by tribal knowledge, a fork can
prove it is compatible by passing them.
