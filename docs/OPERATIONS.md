# Operations

Running interlingua safely: keys, configuration, routers, audit, monitoring.

## 1. Keys

* Generate keys **on the host that will use them** (`il keygen <domain>
  <prefix>` or `il_keygen`). Private keys never need to leave it; only the
  `.pub` bundle is distributed.
* `il keygen` writes the secret bundle with mode `0600` and refuses to
  overwrite an existing file. Store secret bundles like any private key: an
  HSM or the platform keystore (macOS Keychain, Secure Enclave-wrapped storage
  on Apple platforms, a TPM-sealed store on Linux) in production; plain files
  only for development.
* For FIPS 140-3 deployments build with `--no-default-features --features
  fips` and generate keys with that build, so key generation happens inside
  the module's approved mode ([compliance/FIPS-140-3.md](compliance/FIPS-140-3.md)).
* The published keys in `spec/vectors/test-secrets.txt` are **test keys**.
  Never put them in a production keyring.

## 2. Keyrings and policies

* A keyring is a trust store: whoever can edit it decides which keys speak for
  which domain. Build it from `.pub` bundles received over an authenticated
  channel, compare key identifiers (SHA-384, printed by `il keygen`)
  out of band, and keep it under version control with reviewed changes.
* Distribute policy and keyring together, signed (for example with the
  operator's own ML-DSA-87 key or an existing code-signing process), and have
  routers refuse unsigned updates.
* A key belongs to one domain; a keyring with the same key under two domains
  does not load.

## 3. Rotation

| Key | Suggested lifetime | Procedure |
|---|---|---|
| ML-DSA-87 signing | 1–2 years | add the new public bundle to every keyring, switch senders, remove the old bundle after the longest message lifetime has passed |
| ML-KEM-1024 decapsulation | 90 days or less | add the new bundle, switch senders to seal to it, keep the old decapsulation key until in-flight messages expire, then destroy it |

Sealed payloads have **no forward secrecy**: anyone who later obtains a
decapsulation key can open every payload ever sealed to it. Short ML-KEM
lifetimes and real destruction of retired keys are the mitigation.

## 4. Running a router

* One router per domain, with that domain's policy view and keyring.
* Pass trusted time. The library has no clock; the host supplies `now`.
  Synchronise clocks (NTP with authentication, IEEE 1588 PTP, authenticated
  GNSS) to well within `clock-skew`.
* Persist the audit chain and resume it on restart (`Router::resume_audit`,
  or the CLI's `--audit` file, which is verified before it is extended).
* The replay cache is in memory. After a restart, either restore it or wait
  `max-lifetime + clock-skew` before accepting traffic, or accept that
  messages seen before the restart could be replayed once.
* Protect links as well as messages: TLS 1.3 with post-quantum key exchange,
  MACsec, or CCSDS SDLS on space links. The header is visible by design.

## 5. Audit

* Ship audit lines off the host promptly to append-only (WORM) storage.
* Anchor the chain head (`seq` and `hash` of the newest line) periodically:
  sign it and store it where the router cannot rewrite it, or timestamp it
  (RFC 3161). The chain detects edits, insertions, deletions and reordering,
  but only an external anchor detects truncation.
* Verify with `il audit-verify <file>` (exit 0 = intact).
* The fields are single tokens, so `grep`, `awk` and log pipelines parse them
  without a JSON library. `auth=unverified` marks header fields that were
  claims, not facts.

## 6. Monitoring

Alert on:

* any `reason=BadSignature`, `UnknownSigner` or `SignerNotAuthorized`
  (forgery attempts or key-distribution mistakes);
* bursts of `Replay`, `RateLimited` or `Overloaded` (attack or
  misconfiguration);
* `UnexpectedArrival` (a neighbour sending over an edge it should not use);
* label rejections from a source that normally sends cleanly (a policy drift
  or a compromised sender);
* a broken audit chain, or a chain head that stops advancing.

## 7. Incident response

* **Suspected key compromise**: remove the public bundle from every keyring
  (its signatures stop verifying at once), generate a replacement, and review
  the audit trail for messages signed by the old key. For an ML-KEM key,
  assume every payload ever sealed to it is disclosed.
* **Suspected router compromise**: treat the domain's keys as compromised;
  its audit lines from the suspect period are claims, not evidence;
  neighbours' audit chains are the independent record.
