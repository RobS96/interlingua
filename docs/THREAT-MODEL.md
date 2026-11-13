# Threat model

Method: assets and trust boundaries first, then STRIDE per boundary, then
what is mitigated, how, with which evidence, and what is left. Space-segment
threats use the vocabulary of the Aerospace Corporation's SPARTA matrix and
MITRE ATT&CK where they apply. Review this document whenever the wire format,
the cryptography or the router's decision procedure changes.

## 1. Assets

| Asset | Property needed |
|---|---|
| Payload content | confidentiality (when sealed), integrity |
| Header (source, destination, label, times) | integrity, authenticity (it is visible by design) |
| Routing policy and keyring | integrity (whoever edits them decides trust) |
| Signing keys (ML-DSA-87), decapsulation keys (ML-KEM-1024) | confidentiality |
| Audit trail | integrity, completeness |
| Router availability | availability under hostile input and load |

## 2. Trust boundaries

1. **Network ↔ router.** Every byte from a neighbour or link is hostile until
   decoded strictly and verified.
2. **Domain ↔ domain.** A router trusts a neighbour only to deliver bytes
   over an edge the policy defines; it trusts no neighbour's judgement.
3. **Host language ↔ C ABI.** Pointers and lengths from C, Swift, Go and Java
   are checked at the boundary; panics never cross it.
4. **Operator ↔ router.** Policy and keyring are trusted inputs; protecting
   them is the operator's job (OPERATIONS.md).

## 3. Attacker capabilities considered

* On-path attacker: can read, drop, delay, replay, reorder and modify
  envelopes on any link, and inject arbitrary bytes.
* Compromised domain: holds one domain's keys and router; tries to act beyond
  that domain's authority.
* Malicious or careless application in a binding: passes malformed pointers,
  lengths or strings.
* Future quantum adversary: records traffic now to decrypt or forge later.

Out of scope: an attacker in control of the router host or its keys
(they *are* that domain), compromise of the build toolchain beyond what the
supply-chain controls detect, and physical side channels on flight hardware.

## 4. STRIDE analysis

| # | Threat | Boundary | Mitigation | Evidence |
|---|---|---|---|---|
| S1 | Spoof a source domain | 1, 2 | ML-DSA-87 signature by a key the keyring binds to `src` (checks 5–7) | `envelope.rsp` *unknown-signer*, *signer-not-authorized*; `routing.rsp` *spoofed-source* |
| S2 | Present a neighbour as the origin | 2 | arrival check: local origin must equal the node; a neighbour only over a defined edge (check 4) | `routing.rsp` *foreign-origin*, *no-edge-from-sender* |
| T1 | Modify header or payload | 1 | signature over the exact protected bytes and payload | `envelope.rsp` *tampered-payload*, *tampered-signature*; robustness bit flips |
| T2 | Re-encode to change meaning without breaking the signature | 1 | strict deterministic CBOR; signature over received bytes | `cbor.rsp` (149 checks); fuzz `cbor_decode` round trip |
| T3 | Raise the hop budget | 1 | `hops ≤ signed max_hops` (check 11) | `routing.rsp` *hop-count-inflated* |
| T4 | Move a sealed payload under another header | 1 | header in HKDF salt and in AEAD associated data | spec §7.4; `envelope.rsp` *aead-tag-mismatch* |
| R1 | Deny a routing decision happened | 2 | one SHA-384-chained audit line per decision, accepted or not | `audit` tests; `il audit-verify` |
| I1 | Read a payload in transit or at a relay | 1, 2 | ML-KEM-1024 + AES-256-GCM to the destination's key; mandatory from `seal_at` or when the destination requires it | `routing.rsp` *moderate-requires-sealing*, *destination-requires-sealing* |
| I2 | Exfiltrate down to an uncleared domain | 2 | Bell–LaPadula on destination, route ceilings and relays (checks 14, 20) | `routing.rsp` *blp-destination-clearance*, *lab-not-cleared* |
| I3 | Seal to the wrong party | 2 | recipient key must belong to `dst` (check 18) | `routing.rsp` *sealed-to-wrong-domain* |
| I4 | Harvest now, decrypt later | 1 | ML-KEM-1024 and ML-DSA-87 (CNSA 2.0) | CNSA-2.0.md |
| D1 | Crash or hang a router with crafted input | 1, 3 | bounded strict decoders, no panics (catch_unwind at the ABI) | fuzz targets; 100 000-input property test; ASan/UBSan |
| D2 | Flood a router | 1, 2 | per-source token buckets; replay cache bounded and fail-closed (`Overloaded`) | `routing.rsp` *rate-limit* |
| D3 | Replay old traffic | 1 | replay cache until expiry + skew; lifetime ceiling | `routing.rsp` *replay*, *freshness* |
| E1 | A low-integrity domain injects into a high-integrity one | 2 | Biba integrity floor; sources cannot vouch above their own integrity (checks 13, 15) | `routing.rsp` *biba-integrity-floor*, *source-cannot-vouch* |
| E2 | A compromised relay forges traffic from others | 2 | it holds only its own signing key; signatures are end to end | S1 evidence |
| E3 | Memory corruption via a binding | 3 | no `unsafe` outside the ABI crate; every pointer and length checked; outputs reset on entry | C runner under ASan/UBSan; FFI tests |

## 5. Space-segment considerations

| Concern (SPARTA vocabulary) | Response |
|---|---|
| Command-link intrusion (unauthorised telecommands) | telecommands are signed end to end; the spacecraft's router rejects anything not signed by a key bound to an authorised source and flowing over a defined edge |
| Replay of recorded commands | replay cache + lifetime ceiling; CCSDS sequence counts are not relied on for security |
| Ground-segment compromise | domains limit the blast radius: a compromised ground domain can only send what its label clearance and edges allow |
| Link denial | out of scope for the format; framing detects gaps and discards partial messages rather than acting on them |
| Long mission lifetimes | post-quantum algorithms from the start; suite field allows a future transition |

## 6. Residual risks (accepted, documented)

| Risk | Why accepted | Compensating control |
|---|---|---|
| Header metadata (source, destination, label, size, time) is visible | routers must decide without decrypting | link encryption (TLS 1.3, MACsec, SDLS); payload padding |
| No forward secrecy for sealed payloads | static recipient KEM keys keep routers stateless | short ML-KEM key lifetimes (OPERATIONS.md §3) |
| Audit truncation (newest lines deleted) is not detectable from the log alone | a hash chain cannot prove its own end | export signed chain heads to write-once storage |
| Replay protection is per router, not global | global state across domains would be a new trust dependency | destinations keep their own replay cache; applications needing exactly-once add sequence numbers |
| Freshness depends on clocks within `clock-skew` | some segments lack trusted time | generous lifetimes plus replay caches; time from a trusted source where possible (IEEE 1588 PTP, GNSS with authentication) |
| AWS-LC is C and assembly | a validated cryptographic module outweighs a memory-safe but unvalidated one for this purpose | AWS-LC's own fuzzing and formal verification; one module only; see MEMORY-SAFETY-ROADMAP.md |
