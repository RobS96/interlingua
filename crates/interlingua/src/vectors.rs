//! Language-neutral conformance vectors.
//!
//! The files in `spec/vectors/` use the NIST CAVP `.rsp` layout: `#`
//! comments, `[section]` headers, `name = value` fields, blank lines between
//! records. Every language binding parses them itself and checks its own
//! results against them; this module is the reference checker that
//! `cargo test` and `il vectors check` run.
//!
//! | File | Checks |
//! |---|---|
//! | `cbor.rsp` | strict decode accepts/rejects (with the error id), canonical re-encoding |
//! | `label.rsp` | label text and CBOR forms |
//! | `ccsds.rsp` | space packet encode/decode |
//! | `envelope.rsp` | decode, verify, open; error ids for tampered or foreign input |
//! | `routing.rsp` | router verdicts across multi-hop scenarios |

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use crate::ccsds::{PacketType, SequenceFlags, SpacePacket};
use crate::envelope::Envelope;
use crate::error::Error;
use crate::keys::{Keyring, SecretKeys};
use crate::label::Label;
use crate::policy::Policy;
use crate::router::{Router, Verdict};
use crate::{cbor, hex};

/// One record: its section, first line, and fields in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The `[section]` it appears under (empty before the first header).
    pub section: String,
    /// Line number of its first field.
    pub line: usize,
    /// `name = value` pairs.
    pub fields: Vec<(String, String)>,
}

impl Record {
    /// A field's value.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// A required field's value.
    ///
    /// # Errors
    /// [`Error::Vector`] if it is missing.
    pub fn need(&self, name: &str) -> Result<&str, Error> {
        self.get(name)
            .ok_or_else(|| Error::Vector(format!("line {}: missing `{name}`", self.line)))
    }

    fn hex(&self, name: &str) -> Result<Vec<u8>, Error> {
        hex::decode(self.need(name)?)
            .map_err(|_| Error::Vector(format!("line {}: `{name}` is not hex", self.line)))
    }
}

/// Parse `.rsp` text.
///
/// # Errors
/// [`Error::Vector`] for a line that is not a comment, header, blank or field.
pub fn parse(text: &str) -> Result<Vec<Record>, Error> {
    let mut records = Vec::new();
    let mut section = String::new();
    let mut current: Option<Record> = None;
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            records.extend(current.take());
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            records.extend(current.take());
            name.trim().clone_into(&mut section);
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| Error::Vector(format!("line {}: expected `name = value`", index + 1)))?;
        current
            .get_or_insert_with(|| Record {
                section: section.clone(),
                line: index + 1,
                fields: Vec::new(),
            })
            .fields
            .push((key.trim().to_owned(), value.trim().to_owned()));
    }
    records.extend(current);
    Ok(records)
}

/// Outcome of a conformance run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Checks that matched.
    pub passed: usize,
    /// Descriptions of checks that did not.
    pub failures: Vec<String>,
}

impl Report {
    fn check(&mut self, ok: bool, what: impl FnOnce() -> String) {
        if ok {
            self.passed += 1;
        } else {
            self.failures.push(what());
        }
    }

    /// Fold another report into this one.
    pub fn merge(&mut self, other: Self) {
        self.passed += other.passed;
        self.failures.extend(other.failures);
    }

    /// Whether every check matched.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.failures.is_empty()
    }
}

fn unexpected(record: &Record, field: &str) -> Error {
    Error::Vector(format!("line {}: unknown `{field}` value", record.line))
}

/// Check `cbor.rsp`.
///
/// # Errors
/// [`Error::Vector`] if the file itself is malformed.
pub fn check_cbor(text: &str) -> Result<Report, Error> {
    let mut report = Report::default();
    for r in parse(text)? {
        let input = r.hex("cbor")?;
        let decoded = cbor::decode(&input);
        match (r.need("expect")?, decoded) {
            ("accept", Ok(value)) => {
                let again = cbor::encode(&value);
                report.check(again.as_deref() == Ok(input.as_slice()), || {
                    format!("cbor line {}: re-encoding differs", r.line)
                });
                if let Some(want) = r.get("diag") {
                    let got = cbor::diag(&value);
                    report.check(got == want, || {
                        format!("cbor line {}: diag {got} != {want}", r.line)
                    });
                }
            }
            ("accept", Err(e)) => {
                report.check(false, || format!("cbor line {}: rejected ({e})", r.line))
            }
            ("reject", decoded) => {
                let want = r.need("error")?;
                let got = decoded.err().map(|e| Error::Cbor(e).id());
                report.check(got.as_deref() == Some(want), || {
                    format!("cbor line {}: wanted {want}, got {got:?}", r.line)
                });
            }
            _ => return Err(unexpected(&r, "expect")),
        }
    }
    Ok(report)
}

/// Check `label.rsp`.
///
/// # Errors
/// [`Error::Vector`] if the file itself is malformed.
pub fn check_label(text: &str) -> Result<Report, Error> {
    let mut report = Report::default();
    for r in parse(text)? {
        let parsed = Label::parse(r.need("text")?);
        match r.need("expect")? {
            "accept" => {
                let Ok(label) = parsed else {
                    report.check(false, || format!("label line {}: rejected", r.line));
                    continue;
                };
                let want_cbor = r.hex("cbor")?;
                let cbor_ok = cbor::encode(&label.to_cbor()).is_ok_and(|b| b == want_cbor);
                let back_ok = cbor::decode(&want_cbor)
                    .map_err(Error::from)
                    .and_then(|v| Label::from_cbor(&v))
                    .is_ok_and(|l| l == label);
                report.check(label.to_string() == r.need("canonical")?, || {
                    format!("label line {}: canonical text differs", r.line)
                });
                report.check(cbor_ok && back_ok, || {
                    format!("label line {}: CBOR form differs", r.line)
                });
            }
            "reject" => {
                let want = r.need("error")?;
                let got = parsed.err().map(|e| e.id());
                report.check(got.as_deref() == Some(want), || {
                    format!("label line {}: wanted {want}, got {got:?}", r.line)
                });
            }
            _ => return Err(unexpected(&r, "expect")),
        }
    }
    Ok(report)
}

/// Check `ccsds.rsp`.
///
/// # Errors
/// [`Error::Vector`] if the file itself is malformed.
pub fn check_ccsds(text: &str) -> Result<Report, Error> {
    let mut report = Report::default();
    for r in parse(text)? {
        let wire = r.hex("packet")?;
        match r.need("expect")? {
            "accept" => {
                let number = |name: &str| {
                    r.need(name)?.parse::<u16>().map_err(|_| {
                        Error::Vector(format!("line {}: `{name}` is not a number", r.line))
                    })
                };
                let packet = SpacePacket {
                    packet_type: match r.need("type")? {
                        "tm" => PacketType::Telemetry,
                        "tc" => PacketType::Telecommand,
                        _ => return Err(unexpected(&r, "type")),
                    },
                    secondary_header: r.need("sec")? == "1",
                    apid: number("apid")?,
                    flags: match r.need("flags")? {
                        "continuation" => SequenceFlags::Continuation,
                        "first" => SequenceFlags::First,
                        "last" => SequenceFlags::Last,
                        "unsegmented" => SequenceFlags::Unsegmented,
                        _ => return Err(unexpected(&r, "flags")),
                    },
                    sequence_count: number("count")?,
                    data: r.hex("data")?,
                };
                report.check(packet.encode().is_ok_and(|w| w == wire), || {
                    format!("ccsds line {}: encoding differs", r.line)
                });
                report.check(
                    SpacePacket::decode(&wire).is_ok_and(|(p, n)| p == packet && n == wire.len()),
                    || format!("ccsds line {}: decoding differs", r.line),
                );
            }
            "reject" => {
                let got = SpacePacket::decode(&wire).err().map(|e| e.id());
                report.check(got.as_deref() == Some(r.need("error")?), || {
                    format!("ccsds line {}: wanted rejection, got {got:?}", r.line)
                });
            }
            _ => return Err(unexpected(&r, "expect")),
        }
    }
    Ok(report)
}

/// Split concatenated secret bundles (the published test keys).
///
/// # Errors
/// [`Error::Key`] if a bundle does not parse.
pub fn parse_secret_bundles(text: &str) -> Result<BTreeMap<String, SecretKeys>, Error> {
    let mut out = BTreeMap::new();
    let mut current = String::new();
    let mut flush = |chunk: &str| -> Result<(), Error> {
        if chunk
            .lines()
            .any(|l| l.starts_with("interlingua-secret-key"))
        {
            let keys = SecretKeys::parse(chunk)?;
            out.insert(keys.domain.clone(), keys);
        }
        Ok(())
    };
    for line in text.lines() {
        if line.starts_with("interlingua-secret-key") {
            flush(&current)?;
            current.clear();
        }
        current.push_str(line);
        current.push('\n');
    }
    flush(&current)?;
    Ok(out)
}

/// Check `envelope.rsp` against the test keyring and test secrets.
///
/// # Errors
/// [`Error::Vector`] or [`Error::Key`] if the inputs are malformed.
pub fn check_envelope(text: &str, keyring: &str, secrets: &str) -> Result<Report, Error> {
    let ring = Keyring::parse(keyring)?;
    let secrets = parse_secret_bundles(secrets)?;
    let mut report = Report::default();
    for r in parse(text)? {
        let bytes = r.hex("envelope")?;
        let dk = match r.get("recipient") {
            Some(domain) => Some(
                &secrets
                    .get(domain)
                    .ok_or_else(|| {
                        Error::Vector(format!("line {}: no test key for {domain}", r.line))
                    })?
                    .decapsulation,
            ),
            None => None,
        };
        let decoded = Envelope::decode(&bytes);
        if let (Ok(env), Some(_)) = (&decoded, r.get("signed")) {
            let want = r.hex("signed")?;
            report.check(env.signed_bytes().is_ok_and(|b| b == want), || {
                format!("envelope line {}: signed bytes differ", r.line)
            });
        }
        let outcome = decoded.and_then(|env| env.verify_and_open(&ring, dk));
        let name = r.get("name").unwrap_or("?");
        match r.need("expect")? {
            "valid" => {
                let want = r.hex("payload")?;
                report.check(outcome.as_ref().is_ok_and(|p| *p == want), || {
                    format!(
                        "envelope {name}: wanted the payload, got {:?}",
                        outcome.as_ref().map_err(Error::id).err()
                    )
                });
            }
            expect => {
                let want = expect
                    .strip_prefix("error:")
                    .ok_or_else(|| unexpected(&r, "expect"))?;
                let got = outcome.err().map(|e| e.id());
                report.check(got.as_deref() == Some(want), || {
                    format!("envelope {name}: wanted {want}, got {got:?}")
                });
            }
        }
    }
    Ok(report)
}

/// Render a verdict as the vectors spell it.
#[must_use]
pub fn verdict_text(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Deliver => "deliver".to_owned(),
        Verdict::Forward { next_hop } => format!("forward:{next_hop}"),
        Verdict::Reject(reason) => format!("reject:{}", reason.name()),
    }
}

/// Check `routing.rsp`. Each `[section]` starts with fresh routers (one per
/// node named in it); `envelope = forwarded` reuses the previous record's
/// forwarded output.
///
/// # Errors
/// [`Error::Vector`], [`Error::Policy`] or [`Error::Key`] for malformed inputs.
pub fn check_routing(text: &str, policy: &str, keyring: &str) -> Result<Report, Error> {
    let policy = Policy::parse(policy)?;
    let ring = Keyring::parse(keyring)?;
    let mut report = Report::default();
    let mut routers: BTreeMap<String, Router> = BTreeMap::new();
    let mut section: Option<String> = None;
    let mut forwarded: Option<Vec<u8>> = None;
    for r in parse(text)? {
        if section.as_deref() != Some(r.section.as_str()) {
            routers.clear();
            forwarded = None;
            section = Some(r.section.clone());
        }
        let node = r.need("node")?;
        let router = match routers.entry(node.to_owned()) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(Router::new(policy.clone(), ring.clone(), node)?),
        };
        let from = Some(r.need("from")?).filter(|f| *f != "-");
        let now = r
            .need("now")?
            .parse::<u64>()
            .map_err(|_| Error::Vector(format!("line {}: `now` is not a number", r.line)))?;
        let bytes = match r.need("envelope")? {
            "forwarded" => forwarded.clone().ok_or_else(|| {
                Error::Vector(format!("line {}: nothing was forwarded before", r.line))
            })?,
            _ => r.hex("envelope")?,
        };
        let decision = router.route(&bytes, from, now);
        let got = verdict_text(&decision.verdict);
        let want = r.need("expect")?;
        report.check(got == want, || {
            format!(
                "routing [{}] {}: wanted {want}, got {got}",
                r.section,
                r.get("name").unwrap_or("?")
            )
        });
        forwarded = decision.forwarded;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_sections_and_empty_values() {
        let records = super::parse("# c\n[a]\nx = 1\ny =\n\n[b]\nz = k=v\n").unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].section, "a");
        assert_eq!(records[0].get("y"), Some(""));
        assert_eq!(records[1].get("z"), Some("k=v"));
    }
}
