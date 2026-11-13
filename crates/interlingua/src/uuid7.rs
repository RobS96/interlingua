//! UUID version 7 message identifiers (RFC 9562 §5.7): a 48-bit Unix
//! millisecond timestamp followed by 74 random bits. Time-ordered, so audit
//! trails sort naturally; random enough that replay caches can key on them.

use crate::error::Error;

/// Length of a UUID in bytes.
pub const LEN: usize = 16;

/// A new UUIDv7 for `unix_ms`.
///
/// # Errors
/// [`Error::Crypto`] if the system random generator fails, and
/// [`Error::InvalidArgument`] if `unix_ms` does not fit in 48 bits.
pub fn new_v7(unix_ms: u64) -> Result<[u8; LEN], Error> {
    if unix_ms >> 48 != 0 {
        return Err(Error::InvalidArgument(
            "timestamp does not fit a UUIDv7 (48 bits)",
        ));
    }
    let mut id = [0u8; LEN];
    crate::crypto::random(&mut id[6..])?;
    id[..6].copy_from_slice(&unix_ms.to_be_bytes()[2..]);
    id[6] = (id[6] & 0x0f) | 0x70;
    id[8] = (id[8] & 0x3f) | 0x80;
    Ok(id)
}

/// Whether `id` has the version-7 and RFC 9562 variant bits.
#[must_use]
pub fn is_v7(id: &[u8; LEN]) -> bool {
    id[6] >> 4 == 7 && id[8] >> 6 == 0b10
}

/// The millisecond timestamp inside a UUIDv7.
#[must_use]
pub fn timestamp_ms(id: &[u8; LEN]) -> u64 {
    let mut b = [0u8; 8];
    b[2..].copy_from_slice(&id[..6]);
    u64::from_be_bytes(b)
}

/// The canonical 8-4-4-4-12 text form.
#[must_use]
pub fn format(id: &[u8; LEN]) -> String {
    let h = crate::hex::encode(id);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout() {
        let id = new_v7(1_767_225_600_000).unwrap();
        assert!(is_v7(&id));
        assert_eq!(timestamp_ms(&id), 1_767_225_600_000);
        assert_eq!(format(&id).len(), 36);
        // 1_767_225_600_000 = 0x019b_76da_a800 (2026-01-01T00:00:00Z).
        assert!(format(&id).starts_with("019b76da-a800-7"));
        assert!(new_v7(1 << 48).is_err());
    }
}
