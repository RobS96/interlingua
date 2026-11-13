//! Hash-chained audit trail (NIST SP 800-53 AU-3, AU-9, AU-10).
//!
//! Every routing decision becomes one text line of `attr=value` pairs:
//!
//! ```text
//! audit seq=7 time=1767225600000 node=relay … verdict=forward next=space-segment reason=ok code=0 prev=sha384:… hash=sha384:…
//! ```
//!
//! `hash` is SHA-384 of the line up to (not including) ` hash=`, and `prev`
//! is the previous line's `hash` (zeros for the first line). Editing,
//! inserting, deleting or reordering any line breaks the chain. Truncating
//! the end does not, so export the chain head (`seq` and `hash` of the last
//! line) to storage the router cannot rewrite, ideally signed and
//! timestamped (for example with an RFC 3161 time-stamp authority).

use crate::crypto::sha384;
use crate::error::Error;
use crate::hex;

const GENESIS: [u8; 48] = [0u8; 48];

/// Running state of one audit chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditChain {
    seq: u64,
    head: [u8; 48],
}

impl Default for AuditChain {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditChain {
    /// A new chain.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seq: 0,
            head: GENESIS,
        }
    }

    /// Continue an existing chain from its last line's sequence number and hash.
    #[must_use]
    pub const fn resume(seq: u64, head: [u8; 48]) -> Self {
        Self { seq, head }
    }

    /// Sequence number of the last line.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// Hash of the last line.
    #[must_use]
    pub const fn head(&self) -> [u8; 48] {
        self.head
    }

    /// Append a record. Values must be single tokens (no spaces); anything
    /// else is replaced by `?` so a caller cannot forge extra fields.
    pub fn append(&mut self, fields: &[(&str, String)]) -> String {
        let seq = self.seq + 1;
        let mut line = format!("audit seq={seq}");
        for (key, value) in fields {
            let clean: String = value
                .chars()
                .map(|c| {
                    if c.is_ascii_graphic() && c != '=' {
                        c
                    } else {
                        '?'
                    }
                })
                .collect();
            line.push(' ');
            line.push_str(key);
            line.push('=');
            line.push_str(if clean.is_empty() { "-" } else { &clean });
        }
        line.push_str(" prev=sha384:");
        line.push_str(&hex::encode(&self.head));
        let hash = sha384(line.as_bytes());
        line.push_str(" hash=sha384:");
        line.push_str(&hex::encode(&hash));
        self.seq = seq;
        self.head = hash;
        line
    }
}

/// Value of `key` in an audit (or decision) line.
#[must_use]
pub fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split(' ')
        .filter_map(|t| t.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

fn parse_hash(value: Option<&str>) -> Option<[u8; 48]> {
    let hex_text = value?.strip_prefix("sha384:")?;
    hex::decode(hex_text).ok()?.try_into().ok()
}

/// Verify a whole audit text; returns the line count and the chain head.
///
/// # Errors
/// [`Error::Vector`] naming the first line that breaks the chain.
pub fn verify_chain(text: &str) -> Result<AuditChain, Error> {
    let mut chain = AuditChain::new();
    for (index, line) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let n = index + 1;
        let broken = |why: &str| Error::Vector(format!("audit line {n}: {why}"));
        let (body, hash_text) = line
            .rsplit_once(" hash=")
            .ok_or_else(|| broken("no hash"))?;
        let hash =
            parse_hash(Some(hash_text)).ok_or_else(|| broken("hash is not sha384:<96 hex>"))?;
        if sha384(body.as_bytes()) != hash {
            return Err(broken("hash does not match the line"));
        }
        if parse_hash(field(body, "prev")) != Some(chain.head) {
            return Err(broken("prev does not match the previous line"));
        }
        if field(body, "seq").and_then(|s| s.parse::<u64>().ok()) != Some(chain.seq + 1) {
            return Err(broken("seq is out of order"));
        }
        chain = AuditChain::resume(chain.seq + 1, hash);
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_detects_edits_and_reordering() {
        let mut chain = AuditChain::new();
        let a = chain.append(&[("verdict", "deliver".into())]);
        let b = chain.append(&[
            ("verdict", "reject".into()),
            ("evil", "x hash=forged".into()),
        ]);
        assert!(b.contains("evil=x?hash?forged"));
        let text = format!("{a}\n{b}\n");
        assert_eq!(verify_chain(&text).unwrap(), chain);
        assert!(verify_chain(&text.replace("deliver", "forward")).is_err());
        assert!(verify_chain(&format!("{b}\n{a}\n")).is_err());
        assert!(verify_chain(&format!("{b}\n")).is_err());
    }
}
