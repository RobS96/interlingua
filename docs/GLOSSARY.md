# Glossary

| Term | Meaning here |
|---|---|
| **AEAD** | Authenticated encryption with associated data; AES-256-GCM in suite IL1-CNSA2 |
| **APID** | Application Process Identifier, the 11-bit address in a CCSDS Space Packet header |
| **Audit chain** | Audit lines each carrying the SHA-384 of the previous line, so edits are detectable |
| **Bell–LaPadula** | Confidentiality model: information may not flow to a subject not cleared for it ("no write-down") |
| **Biba** | Integrity model: information may not flow from lower to higher integrity ("no write-up") |
| **CBOR** | Concise Binary Object Representation, RFC 8949 |
| **CDDL** | Concise Data Definition Language, RFC 8610 (`spec/interlingua.cddl`) |
| **CCSDS** | Consultative Committee for Space Data Systems; publishes the Space Packet Protocol (133.0-B-2) |
| **CIA triad** | Confidentiality, integrity, availability: the three security objectives of FIPS 199 |
| **Clearance** | A domain's `conf`: the highest confidentiality it may hold |
| **CNSA 2.0** | NSA's Commercial National Security Algorithm Suite 2.0 |
| **Compartment** | A need-to-know category on a label; held by domains, allowed by routes |
| **Deterministic encoding** | One encoding per value (RFC 8949 §4.2.1), enforced on input as well as output |
| **Domain** | A trust domain: an administrative or security boundary named by the operator |
| **Envelope** | The unit interlingua carries: protected header, hop count, payload, signature |
| **FIPS 199** | Federal standard for security categorization (low / moderate / high impact per objective) |
| **Hop** | One forwarding step between routers; bounded by the signed `max_hops` |
| **Interlingua** | A canonical intermediate form every language translates to and from |
| **Keyring** | The set of public key bundles a router trusts, each bound to one domain |
| **Label** | A message's FIPS 199 category plus compartments |
| **ML-DSA-87** | Module-Lattice Digital Signature Algorithm, FIPS 204, the highest parameter set |
| **ML-KEM-1024** | Module-Lattice Key-Encapsulation Mechanism, FIPS 203, the highest parameter set |
| **ndb** | Plan 9's attribute=value database format, the model for policies |
| **Node** | The domain a router serves |
| **Relay** | A domain on a path that is neither the source nor the destination |
| **Seal** | Encrypt a payload end to end to the destination's ML-KEM key |
| **Suite** | A fixed set of algorithms identified by a number in the header (1 = IL1-CNSA2) |
| **Vectors** | The language-neutral conformance test files in `spec/vectors/` |
