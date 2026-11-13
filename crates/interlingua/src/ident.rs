//! Identifier syntax.
//!
//! Domain names, compartments and media types are restricted to lowercase
//! ASCII. Unicode identifiers would need normalization and confusable checks
//! (UTS #39) before two routers could agree that `ground-ops` and a
//! look-alike are different domains; ASCII removes the question. Payloads are
//! opaque bytes and carry any text, in UTF-8 (RFC 3629).

use crate::error::Error;

/// Longest domain name (a DNS label's limit).
pub const MAX_DOMAIN_LEN: usize = 63;
/// Longest compartment name.
pub const MAX_COMPARTMENT_LEN: usize = 32;
/// Longest media type part (type or subtype).
pub const MAX_MEDIA_PART_LEN: usize = 63;

/// Check a trust-domain name: 1–63 of `a-z 0-9 -`, starting with a letter,
/// not ending with `-`.
///
/// # Errors
/// [`Error::Identifier`] describing the broken rule.
pub fn domain(name: &str) -> Result<(), Error> {
    let b = name.as_bytes();
    let (Some(first), Some(last)) = (b.first(), b.last()) else {
        return Err(Error::Identifier("domain name is empty"));
    };
    if b.len() > MAX_DOMAIN_LEN {
        return Err(Error::Identifier(
            "domain name is longer than 63 characters",
        ));
    }
    if !first.is_ascii_lowercase() {
        return Err(Error::Identifier("domain name must start with a-z"));
    }
    if *last == b'-' {
        return Err(Error::Identifier("domain name must not end with '-'"));
    }
    if !b
        .iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
    {
        return Err(Error::Identifier(
            "domain name may contain only a-z, 0-9 and '-'",
        ));
    }
    Ok(())
}

/// Check a compartment name: 1–32 of `a-z 0-9 . -`, starting with a letter or digit.
///
/// # Errors
/// [`Error::Identifier`] describing the broken rule.
pub fn compartment(name: &str) -> Result<(), Error> {
    let b = name.as_bytes();
    let Some(first) = b.first() else {
        return Err(Error::Identifier("compartment is empty"));
    };
    if b.len() > MAX_COMPARTMENT_LEN {
        return Err(Error::Identifier(
            "compartment is longer than 32 characters",
        ));
    }
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(Error::Identifier("compartment must start with a-z or 0-9"));
    }
    if !b
        .iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'.')
    {
        return Err(Error::Identifier(
            "compartment may contain only a-z, 0-9, '.' and '-'",
        ));
    }
    Ok(())
}

fn media_part(part: &str) -> bool {
    let b = part.as_bytes();
    let Some(first) = b.first() else {
        return false;
    };
    b.len() <= MAX_MEDIA_PART_LEN
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"!#$&^_.+-".contains(c))
}

/// Check a media type: `type/subtype` in RFC 6838 restricted-name syntax,
/// lowercase, without parameters (`text/plain`, `application/cbor`).
///
/// # Errors
/// [`Error::Identifier`] if the syntax is broken.
pub fn content_type(media_type: &str) -> Result<(), Error> {
    match media_type.split_once('/') {
        Some((t, s)) if media_part(t) && media_part(s) => Ok(()),
        _ => Err(Error::Identifier(
            "content type must be lowercase type/subtype (RFC 6838 restricted names, no parameters)",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains() {
        for ok in ["a", "ground-ops", "relay7", &"a".repeat(63)] {
            assert!(domain(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "Ground",
            "7relay",
            "ops-",
            "gr\u{f6}und",
            "a_b",
            &"a".repeat(64),
        ] {
            assert!(domain(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn compartments_and_media_types() {
        assert!(compartment("tt-c").is_ok());
        assert!(compartment("2026.q4").is_ok());
        assert!(compartment("-x").is_err());
        assert!(content_type("application/cbor").is_ok());
        assert!(content_type("application/vnd.ccsds.spp+octet").is_ok());
        assert!(content_type("text/plain; charset=utf-8").is_err());
        assert!(content_type("Text/Plain").is_err());
        assert!(content_type("text").is_err());
    }
}
