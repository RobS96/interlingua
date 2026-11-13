//! Lowercase hexadecimal, the text form of every binary field in key bundles,
//! audit records and conformance vectors (every language can read it with
//! no library).

use crate::error::Error;

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Encode bytes as lowercase hex.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decode hex (either case, no separators).
///
/// # Errors
/// [`Error::InvalidArgument`] on odd length or a non-hex character.
pub fn decode(text: &str) -> Result<Vec<u8>, Error> {
    let raw = text.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return Err(Error::InvalidArgument("hex text has odd length"));
    }
    let (pairs, _) = raw.as_chunks::<2>();
    pairs
        .iter()
        .map(|&[hi, lo]| match (nibble(hi), nibble(lo)) {
            (Some(hi), Some(lo)) => Ok((hi << 4) | lo),
            _ => Err(Error::InvalidArgument("hex text has a non-hex character")),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn round_trip() {
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(super::decode(&super::encode(&bytes)).unwrap(), bytes);
        assert_eq!(super::decode("ABcd").unwrap(), vec![0xab, 0xcd]);
        assert!(super::decode("abc").is_err());
        assert!(super::decode("zz").is_err());
    }
}
