# Policy language

A policy names the trust domains, what each may hold, and the directed edges
messages may cross. **Anything not allowed is denied.** The syntax follows
Plan 9's `ndb(6)` network database: plain text, one record per line,
`attr=value` pairs, `#` comments, and indented lines continuing the record
above, so policies diff cleanly and read well in review.

```ndb
# mission.ndb
policy version=1 name=mission max-lifetime=3600 clock-skew=120 seal-at=moderate

domain name=ground-station conf=high     integ=high     avail=high comp=ops,science,tt-c
domain name=relay-sat      conf=moderate integ=moderate avail=high comp=science,tt-c
domain name=spacecraft     conf=moderate integ=high     avail=high comp=tt-c
       integ-floor=moderate sealed=required
domain name=science-lab    conf=low      integ=moderate avail=moderate comp=science
       rate=20 burst=40

route from=ground-station to=relay-sat   bidirectional=yes
route from=relay-sat      to=spacecraft  bidirectional=yes sealed=required
route from=relay-sat      to=science-lab max-conf=low bidirectional=yes
```

## Records

### `policy` (exactly one)

| Attribute | Required | Default | Meaning |
|---|---|---|---|
| `version` | yes | | must be `1` |
| `name` | yes | | identifier (domain syntax) |
| `max-lifetime` | | 86400 | longest `expires − created`, seconds |
| `clock-skew` | | 120 | tolerated clock difference, seconds |
| `seal-at` | | `moderate` | confidentiality from which sealing is mandatory |
| `replay-capacity` | | 100000 | most replay-cache entries per router |

### `domain`

| Attribute | Required | Default | Meaning |
|---|---|---|---|
| `name` | yes | | the domain's identifier |
| `conf` | yes | | **clearance**: highest confidentiality it may hold |
| `integ` | yes | | highest integrity it can **vouch for** in what it sends (≥ low) |
| `avail` | yes | | its availability impact (≥ low) |
| `comp` | | none | compartments it may hold |
| `integ-floor` | | `low` | lowest integrity it **accepts** (≤ `integ`) |
| `sealed` | | `optional` | `required`: everything delivered here must be sealed |
| `rate`, `burst` | | 100, 200 | token bucket for messages it originates, per router |

### `route`

| Attribute | Required | Default | Meaning |
|---|---|---|---|
| `from`, `to` | yes | | an allowed directed edge |
| `max-conf` | | lower clearance of the two | highest confidentiality that may cross |
| `comp` | | compartments both ends hold | compartments that may cross |
| `sealed` | | `optional` | `required`: only sealed envelopes cross |
| `max-bytes` | | 1048576 | largest encoded envelope that may cross |
| `bidirectional` | | `no` | `yes` also defines the reverse edge |

## How the rules combine

For a message with label *L* from *S* to *D*:

1. *S* may originate it: `L.conf ≤ S.conf`, `L.integ ≤ S.integ`, compartments
   held by *S*.
2. *D* may receive it: `L.conf ≤ D.conf` (**Bell–LaPadula**: no flow to an
   uncleared domain), `L.integ ≥ D.integ-floor` (**Biba**: no flow of
   lower-integrity data into a domain that demands more), compartments held
   by *D*.
3. It is sealed if `L.conf ≥ seal-at` or *D* requires sealing.
4. A path exists in which every edge allows *L*, the sealing state and the
   size, and every relay could hold *L* itself.

Each router evaluates these against its own copy of the policy, at every hop.
The full ordered procedure, with the reason reported for each failure, is in
[SPECIFICATION.md §8](SPECIFICATION.md#8-router-processing).

## Validation at load time

A policy that is ambiguous does not load. Errors name the line:

* unknown record types or attributes, repeated attributes, characters outside
  `[A-Za-z0-9._,:/+-]` in values;
* more or fewer than one `policy` record, or a `version` other than 1;
* duplicate domains, routes naming unknown domains, self-routes, duplicate
  edges (including those created by `bidirectional=yes`);
* a route `max-conf` above either endpoint's clearance, or route compartments
  an endpoint may not hold;
* `integ` or `avail` of `n/a`, an `integ-floor` above the domain's `integ`,
  numbers outside their ranges.

## Writing good policies

* Start from no routes and add the edges the mission needs; every edge is a
  decision someone should be able to explain.
* Give relays the lowest clearance that still carries the traffic they must
  relay; sealed payloads do not need relays to be cleared for their content
  to stay confidential, but the label check still applies.
* Use `integ-floor` on command-receiving domains (spacecraft, actuators) so
  only high-integrity sources can reach them.
* Keep `max-lifetime` short for commands and longer only where links are
  intermittent.
* Treat the policy and keyring files as security-critical configuration:
  version-control them, review changes, and distribute them signed
  ([OPERATIONS.md](OPERATIONS.md)).
