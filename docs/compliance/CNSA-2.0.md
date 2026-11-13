# CNSA 2.0

NSA's Commercial National Security Algorithm Suite 2.0 (announced September
2022, with later FAQ updates) lists the algorithms approved for national
security systems as they move to quantum-resistant cryptography.

## Algorithms

| CNSA 2.0 function | Required algorithm | interlingua (suite IL1-CNSA2) |
|---|---|---|
| Symmetric encryption | AES-256 (FIPS 197) | AES-256-GCM (SP 800-38D) for sealed payloads |
| Hashing | SHA-384 or SHA-512 (FIPS 180-4) | SHA-384: key identifiers, HKDF, audit chain, header salt |
| Key establishment | ML-KEM-1024 (FIPS 203) | ML-KEM-1024, a fresh encapsulation per sealed message |
| Digital signatures | ML-DSA-87 (FIPS 204) | ML-DSA-87, pure mode, on every envelope |
| Software and firmware signing | LMS or XMSS (SP 800-208) | not used (interlingua signs messages, not firmware); an LMS/XMSS suite is on the [roadmap](../ROADMAP.md) for update envelopes |
| Key derivation | (from SP 800-56C) | HKDF with SHA-384 |

Only the highest parameter sets are used. There is one suite per wire-format
version and no negotiation, so no peer can push a session to a weaker
algorithm. Classical algorithms (RSA, ECDH, ECDSA) are not used at all.

## Transition timeline

NSA's published timeline (check the current CNSA 2.0 advisory and FAQ for
updates) asks systems to support and prefer CNSA 2.0, then use it
exclusively, by category:

| Category | Support and prefer by | Exclusively by |
|---|---|---|
| Software and firmware signing | 2025 | 2030 |
| Web browsers, servers and cloud services | 2025 | 2033 |
| Traditional networking equipment (VPNs, routers) | 2026 | 2030 |
| Operating systems | 2027 | 2033 |
| Niche equipment | 2030 | 2033 |
| Custom applications and legacy equipment | update or replace by 2033 | |

interlingua uses CNSA 2.0 algorithms **exclusively from its first version**,
ahead of every milestone in the table.

## Interoperability evidence

The same ML-DSA-87 keys (derived from published FIPS 204 seeds), signatures,
ML-KEM-1024 key encapsulations and HKDF-SHA-384 derivations are checked by
four implementations that share no code: AWS-LC (the reference), Apple
CryptoKit, Go's standard library and OpenSSL 3.5+ (and the JDK in CI). See
the [README](../../README.md#proven-interoperability).

## What the operator still owns

Running on a CNSA 2.0 algorithm set is necessary, not sufficient, for an
NSS: the cryptographic module must be validated (FIPS-140-3.md), keys
managed accordingly, and the system authorized under the applicable
CNSS policies.
