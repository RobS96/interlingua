//! Routing policy.
//!
//! A policy names the trust domains, what each may hold, and the directed
//! edges messages may cross. Anything not allowed is denied. The format
//! follows Plan 9's `ndb(6)`: one record per line, `attr=value` pairs, `#`
//! comments, and indented lines continuing the record above.
//!
//! ```text
//! policy version=1 name=demo max-lifetime=86400 clock-skew=120 seal-at=moderate
//! domain name=ground-ops conf=high integ=high avail=high comp=ops,tt-c
//!        integ-floor=moderate sealed=required rate=50 burst=100
//! route  from=ground-ops to=relay max-conf=moderate comp=tt-c bidirectional=yes
//! ```
//!
//! Records and attributes (`docs/POLICY.md` has the full reference):
//!
//! * `policy`: `version` (required, 1), `name` (required), `max-lifetime` and
//!   `clock-skew` in seconds (86400, 120), `seal-at` (confidentiality from
//!   which a sealed payload is mandatory, `moderate`), `replay-capacity`
//!   (100000).
//! * `domain`: `name`, `conf` (clearance: highest confidentiality it may
//!   hold), `integ` (highest integrity it can vouch for), `avail`
//!   (required); `comp` compartments it may hold; `integ-floor` (lowest
//!   integrity it accepts, `low`); `sealed=required|optional`; `rate` and
//!   `burst` for messages it originates (100/s, 200).
//! * `route`: `from`, `to` (required); `max-conf` (default the lower of the
//!   two clearances); `comp` (default the compartments both domains hold);
//!   `sealed`; `max-bytes` (1048576); `bidirectional=yes|no`.
//!
//! Load-time checks reject anything ambiguous: unknown attributes, duplicates,
//! routes to unknown domains, self-routes, and route limits above either
//! endpoint's clearance.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::Error;
use crate::ident;
use crate::label::Impact;

/// Longest accepted policy line.
pub const MAX_LINE_LEN: usize = 4096;

/// A trust domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    /// Domain name.
    pub name: String,
    /// Clearance: highest confidentiality impact the domain may hold.
    pub confidentiality: Impact,
    /// Highest integrity impact the domain can vouch for in what it sends.
    pub integrity: Impact,
    /// Lowest integrity impact the domain accepts.
    pub integrity_floor: Impact,
    /// The domain's availability impact.
    pub availability: Impact,
    /// Compartments the domain may hold.
    pub compartments: BTreeSet<String>,
    /// Every message delivered to this domain must be sealed.
    pub sealed_required: bool,
    /// Messages per second this domain may originate through one router.
    pub rate_per_sec: u64,
    /// Burst allowance for the rate limit.
    pub burst: u64,
}

/// A directed edge between domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Sending domain.
    pub from: String,
    /// Receiving domain.
    pub to: String,
    /// Highest confidentiality that may cross.
    pub max_confidentiality: Impact,
    /// Compartments that may cross.
    pub compartments: BTreeSet<String>,
    /// Messages on this edge must be sealed.
    pub sealed_required: bool,
    /// Largest encoded envelope that may cross, in bytes.
    pub max_bytes: usize,
}

/// A validated policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Policy name.
    pub name: String,
    /// Longest permitted message lifetime (expires − created), ms.
    pub max_lifetime_ms: u64,
    /// Tolerated clock skew, ms.
    pub clock_skew_ms: u64,
    /// Confidentiality from which a sealed payload is mandatory.
    pub seal_at: Impact,
    /// Most replay-cache entries one router keeps.
    pub replay_capacity: usize,
    /// Domains by name.
    pub domains: BTreeMap<String, Domain>,
    /// Routes by sender, then receiver.
    pub routes: BTreeMap<String, BTreeMap<String, Route>>,
}

struct Record {
    line: usize,
    kind: String,
    attrs: Vec<(String, String)>,
}

fn err(line: usize, message: impl Into<String>) -> Error {
    Error::Policy {
        line,
        message: message.into(),
    }
}

fn tokenize(text: &str) -> Result<Vec<Record>, Error> {
    let mut records: Vec<Record> = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        if raw.len() > MAX_LINE_LEN {
            return Err(err(line, "line is longer than 4096 bytes"));
        }
        let content = raw.split_once('#').map_or(raw, |(before, _)| before);
        if content.trim().is_empty() {
            continue;
        }
        let continuation = raw.starts_with([' ', '\t']);
        let mut tokens = content.split_ascii_whitespace();
        if !continuation {
            let kind = tokens.next().unwrap_or_default().to_owned();
            records.push(Record {
                line,
                kind,
                attrs: Vec::new(),
            });
        }
        let record = records
            .last_mut()
            .ok_or_else(|| err(line, "continuation line before any record"))?;
        for token in tokens {
            let (key, value) = token
                .split_once('=')
                .ok_or_else(|| err(line, format!("`{token}` is not attr=value")))?;
            let key_ok =
                !key.is_empty() && key.bytes().all(|c| c.is_ascii_lowercase() || c == b'-');
            let value_ok = !value.is_empty()
                && value
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._,:/+-".contains(&c));
            if !key_ok || !value_ok {
                return Err(err(
                    line,
                    format!("`{token}` has characters outside the policy syntax"),
                ));
            }
            record.attrs.push((key.to_owned(), value.to_owned()));
        }
    }
    Ok(records)
}

struct Attrs<'r> {
    line: usize,
    map: BTreeMap<&'r str, &'r str>,
}

impl<'r> Attrs<'r> {
    fn new(record: &'r Record, allowed: &[&str]) -> Result<Self, Error> {
        let mut map = BTreeMap::new();
        for (k, v) in &record.attrs {
            if !allowed.contains(&k.as_str()) {
                return Err(err(
                    record.line,
                    format!("`{}` records have no `{k}` attribute", record.kind),
                ));
            }
            if map.insert(k.as_str(), v.as_str()).is_some() {
                return Err(err(record.line, format!("`{k}` appears twice")));
            }
        }
        Ok(Self {
            line: record.line,
            map,
        })
    }

    fn opt(&self, key: &str) -> Option<&'r str> {
        self.map.get(key).copied()
    }

    fn req(&self, key: &str) -> Result<&'r str, Error> {
        self.opt(key)
            .ok_or_else(|| err(self.line, format!("`{key}` is required")))
    }

    fn impact(&self, key: &str) -> Result<Option<Impact>, Error> {
        self.opt(key)
            .map(|v| Impact::parse(v).map_err(|e| err(self.line, format!("`{key}`: {e}"))))
            .transpose()
    }

    fn number(&self, key: &str, max: u64) -> Result<Option<u64>, Error> {
        self.opt(key)
            .map(|v| {
                v.parse::<u64>()
                    .ok()
                    .filter(|n| v.bytes().all(|c| c.is_ascii_digit()) && (1..=max).contains(n))
                    .ok_or_else(|| {
                        err(self.line, format!("`{key}` must be a whole number 1-{max}"))
                    })
            })
            .transpose()
    }

    fn flag(&self, key: &str, yes: &str, no: &str) -> Result<bool, Error> {
        match self.opt(key) {
            None => Ok(false),
            Some(v) if v == yes => Ok(true),
            Some(v) if v == no => Ok(false),
            Some(_) => Err(err(self.line, format!("`{key}` must be {yes} or {no}"))),
        }
    }

    fn compartments(&self, key: &str) -> Result<Option<BTreeSet<String>>, Error> {
        let Some(list) = self.opt(key) else {
            return Ok(None);
        };
        let mut set = BTreeSet::new();
        for c in list.split(',') {
            ident::compartment(c).map_err(|e| err(self.line, e.to_string()))?;
            if !set.insert(c.to_owned()) {
                return Err(err(self.line, format!("compartment `{c}` appears twice")));
            }
        }
        Ok(Some(set))
    }
}

const SECOND_MS: u64 = 1000;

impl Policy {
    /// Parse and validate policy text.
    ///
    /// # Errors
    /// [`Error::Policy`] with the line of the first problem.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let records = tokenize(text)?;
        let mut header: Option<Policy> = None;
        let mut domains = BTreeMap::new();
        let mut pending_routes = Vec::new();
        for record in &records {
            match record.kind.as_str() {
                "policy" => {
                    let a = Attrs::new(
                        record,
                        &[
                            "version",
                            "name",
                            "max-lifetime",
                            "clock-skew",
                            "seal-at",
                            "replay-capacity",
                        ],
                    )?;
                    if header.is_some() {
                        return Err(err(record.line, "more than one `policy` record"));
                    }
                    if a.req("version")? != "1" {
                        return Err(err(record.line, "only policy version=1 is defined"));
                    }
                    let name = a.req("name")?;
                    ident::domain(name)
                        .map_err(|e| err(record.line, format!("policy name: {e}")))?;
                    header = Some(Policy {
                        name: name.to_owned(),
                        max_lifetime_ms: a.number("max-lifetime", 31_536_000)?.unwrap_or(86_400)
                            * SECOND_MS,
                        clock_skew_ms: a.number("clock-skew", 3_600)?.unwrap_or(120) * SECOND_MS,
                        seal_at: a.impact("seal-at")?.unwrap_or(Impact::Moderate),
                        replay_capacity: usize::try_from(
                            a.number("replay-capacity", 100_000_000)?.unwrap_or(100_000),
                        )
                        .map_err(|_| err(record.line, "replay-capacity is too large"))?,
                        domains: BTreeMap::new(),
                        routes: BTreeMap::new(),
                    });
                }
                "domain" => {
                    let a = Attrs::new(
                        record,
                        &[
                            "name",
                            "conf",
                            "integ",
                            "avail",
                            "comp",
                            "integ-floor",
                            "sealed",
                            "rate",
                            "burst",
                        ],
                    )?;
                    let name = a.req("name")?;
                    ident::domain(name).map_err(|e| err(record.line, e.to_string()))?;
                    let impact = |k: &str| {
                        a.impact(k)?
                            .ok_or_else(|| err(record.line, format!("`{k}` is required")))
                    };
                    let domain = Domain {
                        name: name.to_owned(),
                        confidentiality: impact("conf")?,
                        integrity: impact("integ")?,
                        integrity_floor: a.impact("integ-floor")?.unwrap_or(Impact::Low),
                        availability: impact("avail")?,
                        compartments: a.compartments("comp")?.unwrap_or_default(),
                        sealed_required: a.flag("sealed", "required", "optional")?,
                        rate_per_sec: a.number("rate", 1_000_000)?.unwrap_or(100),
                        burst: a.number("burst", 1_000_000)?.unwrap_or(200),
                    };
                    if domain.integrity == Impact::NotApplicable
                        || domain.availability == Impact::NotApplicable
                    {
                        return Err(err(
                            record.line,
                            "integ and avail are at least low (FIPS 199)",
                        ));
                    }
                    if domain.integrity_floor > domain.integrity {
                        return Err(err(
                            record.line,
                            "integ-floor is above the domain's own integ",
                        ));
                    }
                    if domains.insert(name.to_owned(), domain).is_some() {
                        return Err(err(
                            record.line,
                            format!("domain `{name}` is defined twice"),
                        ));
                    }
                }
                "route" => pending_routes.push(record),
                other => return Err(err(record.line, format!("unknown record type `{other}`"))),
            }
        }
        let mut policy =
            header.ok_or_else(|| err(0, "a `policy version=1 name=…` record is required"))?;
        if domains.is_empty() {
            return Err(err(0, "the policy defines no domains"));
        }
        for record in pending_routes {
            let a = Attrs::new(
                record,
                &[
                    "from",
                    "to",
                    "max-conf",
                    "comp",
                    "sealed",
                    "max-bytes",
                    "bidirectional",
                ],
            )?;
            let (from, to) = (a.req("from")?, a.req("to")?);
            let (Some(f), Some(t)) = (domains.get(from), domains.get(to)) else {
                return Err(err(
                    record.line,
                    "route names a domain the policy does not define",
                ));
            };
            if from == to {
                return Err(err(record.line, "a route needs two different domains"));
            }
            let ceiling = f.confidentiality.min(t.confidentiality);
            let max_confidentiality = a.impact("max-conf")?.unwrap_or(ceiling);
            if max_confidentiality > ceiling {
                return Err(err(
                    record.line,
                    "max-conf is above an endpoint's clearance",
                ));
            }
            let shared: BTreeSet<String> = f
                .compartments
                .intersection(&t.compartments)
                .cloned()
                .collect();
            let compartments = a.compartments("comp")?.unwrap_or_else(|| shared.clone());
            if !compartments.is_subset(&shared) {
                return Err(err(
                    record.line,
                    "comp names a compartment an endpoint may not hold",
                ));
            }
            let route = Route {
                from: from.to_owned(),
                to: to.to_owned(),
                max_confidentiality,
                compartments,
                sealed_required: a.flag("sealed", "required", "optional")?,
                max_bytes: usize::try_from(
                    a.number("max-bytes", 16 * 1024 * 1024)?.unwrap_or(1 << 20),
                )
                .map_err(|_| err(record.line, "max-bytes is too large"))?,
            };
            let reverse = a.flag("bidirectional", "yes", "no")?.then(|| Route {
                from: route.to.clone(),
                to: route.from.clone(),
                ..route.clone()
            });
            for r in std::iter::once(route).chain(reverse) {
                let edges = policy.routes.entry(r.from.clone()).or_default();
                if edges.contains_key(&r.to) {
                    return Err(err(
                        record.line,
                        format!("route {} -> {} is defined twice", r.from, r.to),
                    ));
                }
                edges.insert(r.to.clone(), r);
            }
        }
        policy.domains = domains;
        Ok(policy)
    }

    /// A domain by name.
    #[must_use]
    pub fn domain(&self, name: &str) -> Option<&Domain> {
        self.domains.get(name)
    }

    /// The edge `from → to`, if allowed.
    #[must_use]
    pub fn route(&self, from: &str, to: &str) -> Option<&Route> {
        self.routes.get(from).and_then(|edges| edges.get(to))
    }

    /// Edges leaving `from`, in name order (so path choice is deterministic).
    pub fn routes_from(&self, from: &str) -> impl Iterator<Item = &Route> {
        self.routes.get(from).into_iter().flat_map(BTreeMap::values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO: &str = "\
# demo
policy version=1 name=demo max-lifetime=3600
domain name=ground conf=high integ=high avail=high comp=ops,tt-c
       sealed=required
domain name=relay conf=moderate integ=moderate avail=high comp=tt-c
route from=ground to=relay max-conf=moderate bidirectional=yes
";

    #[test]
    fn parses_with_continuations_and_defaults() {
        let p = Policy::parse(DEMO).unwrap();
        assert_eq!(p.max_lifetime_ms, 3_600_000);
        assert_eq!(p.clock_skew_ms, 120_000);
        assert!(p.domain("ground").unwrap().sealed_required);
        let r = p.route("relay", "ground").unwrap();
        assert_eq!(r.max_confidentiality, Impact::Moderate);
        assert_eq!(r.compartments.iter().collect::<Vec<_>>(), ["tt-c"]);
        assert!(p.route("ground", "ground").is_none());
    }

    #[test]
    fn rejects_ambiguity() {
        let cases = [
            (
                "policy version=2 name=x\ndomain name=a conf=low integ=low avail=low",
                1,
            ),
            (
                "policy version=1 name=x\ndomain name=a conf=low integ=low avail=low colour=red",
                2,
            ),
            (
                "policy version=1 name=x\ndomain name=a conf=low integ=low avail=low\ndomain name=a conf=low integ=low avail=low",
                3,
            ),
            (
                "policy version=1 name=x\ndomain name=a conf=low integ=low avail=low\nroute from=a to=b",
                3,
            ),
            (
                "policy version=1 name=x\ndomain name=a conf=low integ=low avail=low\ndomain name=b conf=high integ=low avail=low\nroute from=a to=b max-conf=high",
                4,
            ),
            (
                "policy version=1 name=x\ndomain name=a conf=low integ=n/a avail=low",
                2,
            ),
            (
                "policy version=1 name=x\ndomain name=a conf=low integ=low avail=low rate=0",
                2,
            ),
            (
                "policy version=1 name=x\ndomain name=a conf=low integ=low avail=low comp=a;b",
                2,
            ),
        ];
        for (text, line) in cases {
            match Policy::parse(text) {
                Err(Error::Policy { line: got, .. }) => assert_eq!(got, line, "{text}"),
                other => panic!("{text}: expected a policy error, got {other:?}"),
            }
        }
    }
}
