# FIPS 199 and CNSSI 1253: the C-I-A triad

## Security categories on every message

FIPS 199 (*Standards for Security Categorization of Federal Information and
Information Systems*) categorizes information by the potential impact of a
loss of each security objective: **confidentiality, integrity,
availability**. The impact is LOW, MODERATE or HIGH; for confidentiality only,
"not applicable" is allowed for public information.

interlingua puts that category on every message, inside the signed header:

```
label = [confidentiality, integrity, availability, [compartments]]
text:   conf=moderate integ=high avail=high comp=tt-c
```

## How each objective is enforced

| Objective | Mechanism in the router | Model |
|---|---|---|
| Confidentiality | a message reaches only domains cleared for its `conf`, over edges and relays allowed to carry it; from `seal-at` up it must be sealed end to end | Bell–LaPadula (no write-down) |
| Integrity | a source cannot claim more integrity than it has; a destination refuses messages below its integrity floor; every message is signed | Biba (no write-up of lower-integrity data) |
| Availability | per-source rate limits, bounded resources, fail-closed caches; the `avail` impact is carried and audited for host-side scheduling (queue priority) | |

## CNSSI No. 1253

CNSSI 1253 applies FIPS 199-style categorization to national security
systems, but keeps the confidentiality, integrity and availability values
separate when selecting controls instead of collapsing them to a single
high-water mark, and adds overlays. interlingua's labels keep the three
values separate for the same reason: a telecommand to a spacecraft can be
MODERATE for confidentiality but HIGH for integrity, and the router enforces
each objective with its own rule.

## Compartments

Compartments express need-to-know independently of impact levels: a message
in compartment `tt-c` reaches only domains that hold `tt-c`, over edges that
allow it. Domains declare the compartments they may hold in the policy.

## Limits: classified information

Labels implement an information-flow policy in software. They do **not**
make a system suitable for classified information, and interlingua is not a
cross-domain solution. Moving information between security domains of
different classification requires an accredited system using an assessed
cross-domain solution (in the U.S., one from the NCDSMO baseline). Use
interlingua's labels for impact categorization and need-to-know separation
within the authorization boundary you already have.
