//! Strict deterministic CBOR (RFC 8949).
//!
//! interlingua's canonical form is RFC 8949 §4.2.1 "Core Deterministic
//! Encoding", applied strictly on input as well as output: a decoder that
//! accepted two encodings of one value would let two implementations disagree
//! about the bytes a signature covers. So the decoder rejects:
//!
//! * integers, lengths and counts not in their shortest form;
//! * indefinite-length items, tags, `undefined` and unassigned simple values;
//! * floats that a narrower IEEE 754-2019 width (binary16 → binary32 →
//!   binary64) represents exactly, and every NaN except `0xf97e00`;
//! * map keys that are duplicated or not in bytewise lexicographic order of
//!   their encodings;
//! * text that is not UTF-8, and anything after the top-level item.
//!
//! The encoder produces exactly that form, so `encode(decode(x)) == x` for
//! every accepted `x`.

use core::cmp::Ordering;
use core::fmt::Write as _;

use crate::error::CborError;

/// Resource limits for decoding untrusted input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Deepest nesting of arrays and maps (the top-level item is depth 0).
    pub max_depth: usize,
    /// Most items in a single array or entries in a single map.
    pub max_items: usize,
    /// Longest input, and longest single byte or text string, in bytes.
    pub max_len: usize,
}

impl Limits {
    /// The limits every interlingua object is decoded with.
    pub const DEFAULT: Self = Self {
        max_depth: 16,
        max_items: 4096,
        max_len: 16 * 1024 * 1024,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The CBOR data model interlingua supports.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Major type 0.
    Unsigned(u64),
    /// Major type 1: the value `-1 - n`.
    Negative(u64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3 (always valid UTF-8).
    Text(String),
    /// Major type 4.
    Array(Vec<Value>),
    /// Major type 5. Encoding sorts the entries; decoding returns them sorted.
    Map(Vec<(Value, Value)>),
    /// `false` / `true`.
    Bool(bool),
    /// `null`.
    Null,
    /// An IEEE 754 binary64 value, encoded in its preferred (shortest exact) width.
    Float(f64),
}

impl Value {
    /// The value as an unsigned integer.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Unsigned(n) => Some(*n),
            _ => None,
        }
    }

    /// The value as a byte string.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The value as a text string.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s),
            _ => None,
        }
    }

    /// The value as an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The value as a map, entries in canonical order.
    #[must_use]
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Self::Map(entries) => Some(entries),
            _ => None,
        }
    }

    /// The value as a boolean.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// Encode a value in deterministic form.
///
/// # Errors
/// [`CborError::DuplicateMapKey`] if a map has two equal keys, and the
/// [`Limits::DEFAULT`] errors for values the decoder would refuse.
pub fn encode(value: &Value) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    encode_into(value, &mut out, 0)?;
    if out.len() > Limits::DEFAULT.max_len {
        return Err(CborError::TooLarge);
    }
    Ok(out)
}

fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if let Ok(small) = u8::try_from(arg) {
        if small < 24 {
            out.push(m | small);
        } else {
            out.push(m | 24);
            out.push(small);
        }
    } else if let Ok(v) = u16::try_from(arg) {
        out.push(m | 25);
        out.extend_from_slice(&v.to_be_bytes());
    } else if let Ok(v) = u32::try_from(arg) {
        out.push(m | 26);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn len_u64(n: usize) -> u64 {
    // usize is at most 64 bits on every supported target.
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn encode_into(value: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), CborError> {
    let limits = Limits::DEFAULT;
    if depth > limits.max_depth {
        return Err(CborError::DepthExceeded);
    }
    match value {
        Value::Unsigned(n) => head(out, 0, *n),
        Value::Negative(n) => head(out, 1, *n),
        Value::Bytes(b) => {
            if b.len() > limits.max_len {
                return Err(CborError::TooLarge);
            }
            head(out, 2, len_u64(b.len()));
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            if s.len() > limits.max_len {
                return Err(CborError::TooLarge);
            }
            head(out, 3, len_u64(s.len()));
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            if items.len() > limits.max_items {
                return Err(CborError::TooManyItems);
            }
            head(out, 4, len_u64(items.len()));
            for item in items {
                encode_into(item, out, depth + 1)?;
            }
        }
        Value::Map(entries) => {
            if entries.len() > limits.max_items {
                return Err(CborError::TooManyItems);
            }
            let mut encoded = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let mut kb = Vec::new();
                encode_into(k, &mut kb, depth + 1)?;
                let mut vb = Vec::new();
                encode_into(v, &mut vb, depth + 1)?;
                encoded.push((kb, vb));
            }
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            if encoded.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(CborError::DuplicateMapKey);
            }
            head(out, 5, len_u64(encoded.len()));
            for (k, v) in encoded {
                out.extend_from_slice(&k);
                out.extend_from_slice(&v);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
        Value::Float(f) => encode_float(*f, out),
    }
    Ok(())
}

fn encode_float(f: f64, out: &mut Vec<u8>) {
    if f.is_nan() {
        out.extend_from_slice(&[0xf9, 0x7e, 0x00]);
    } else if let Some(h) = f64_to_f16_exact(f) {
        out.push(0xf9);
        out.extend_from_slice(&h.to_be_bytes());
    } else if let Some(s) = f64_to_f32_exact(f) {
        out.push(0xfa);
        out.extend_from_slice(&s.to_bits().to_be_bytes());
    } else {
        out.push(0xfb);
        out.extend_from_slice(&f.to_bits().to_be_bytes());
    }
}

/// The binary16 bit pattern that represents `f` exactly, if one exists.
/// Every NaN maps to the canonical quiet NaN `0x7e00`.
#[must_use]
pub fn f64_to_f16_exact(f: f64) -> Option<u16> {
    let bits = f.to_bits();
    let sign = u16::try_from((bits >> 48) & 0x8000).ok()?;
    let exp_field = (bits >> 52) & 0x7ff;
    let mant = bits & 0x000f_ffff_ffff_ffff;
    if exp_field == 0x7ff {
        return Some(if mant == 0 { sign | 0x7c00 } else { 0x7e00 });
    }
    if exp_field == 0 {
        // Zero keeps its sign; binary64 subnormals are far below binary16's range.
        return if mant == 0 { Some(sign) } else { None };
    }
    let exp = i64::try_from(exp_field).ok()? - 1023;
    if exp > 15 {
        return None;
    }
    if exp >= -14 {
        // Normal binary16: the 42 low mantissa bits must be zero.
        if mant & ((1u64 << 42) - 1) != 0 {
            return None;
        }
        let e16 = u16::try_from(exp + 15).ok()?;
        let m16 = u16::try_from(mant >> 42).ok()?;
        return Some(sign | (e16 << 10) | m16);
    }
    if exp < -24 {
        return None;
    }
    // Subnormal binary16: value = m × 2^-24 with 1 <= m <= 1023.
    let significand = mant | (1u64 << 52);
    let shift = u32::try_from(52 - (exp + 24)).ok()?;
    if significand & ((1u64 << shift) - 1) != 0 {
        return None;
    }
    let m16 = u16::try_from(significand >> shift).ok()?;
    Some(sign | m16)
}

/// The binary32 value that represents finite, non-zero `f` exactly, if one exists.
#[must_use]
#[allow(clippy::cast_possible_truncation)] // the round trip below proves exactness
pub fn f64_to_f32_exact(f: f64) -> Option<f32> {
    let s = f as f32;
    if s.is_finite() && f64::from(s) == f {
        Some(s)
    } else {
        None
    }
}

/// The value of a binary16 bit pattern.
#[must_use]
pub fn f16_to_f64(h: u16) -> f64 {
    let sign = if h & 0x8000 == 0 { 1.0 } else { -1.0 };
    let exp = (h >> 10) & 0x1f;
    let mant = f64::from(h & 0x03ff);
    match exp {
        0 => sign * mant * 2.0f64.powi(-24),
        31 => {
            if mant == 0.0 {
                sign * f64::INFINITY
            } else {
                f64::NAN
            }
        }
        e => sign * (1.0 + mant / 1024.0) * 2.0f64.powi(i32::from(e) - 15),
    }
}

/// Decode one deterministic CBOR item that must span the whole input.
///
/// # Errors
/// Any [`CborError`]; see the module documentation for what is refused.
pub fn decode(bytes: &[u8]) -> Result<Value, CborError> {
    decode_with(bytes, Limits::DEFAULT)
}

/// [`decode`] with explicit limits.
///
/// # Errors
/// Any [`CborError`].
pub fn decode_with(bytes: &[u8], limits: Limits) -> Result<Value, CborError> {
    if bytes.len() > limits.max_len {
        return Err(CborError::TooLarge);
    }
    let mut d = Decoder {
        buf: bytes,
        pos: 0,
        limits,
    };
    let value = d.value(0)?;
    if d.pos != bytes.len() {
        return Err(CborError::TrailingBytes);
    }
    Ok(value)
}

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
    limits: Limits,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self.pos.checked_add(n).ok_or(CborError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(CborError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, CborError> {
        self.take(1)?.first().copied().ok_or(CborError::Truncated)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], CborError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn argument(&mut self, info: u8) -> Result<u64, CborError> {
        match info {
            0..=23 => Ok(u64::from(info)),
            24 => {
                let v = u64::from(self.byte()?);
                if v < 24 {
                    Err(CborError::NonCanonicalInteger)
                } else {
                    Ok(v)
                }
            }
            25 => {
                let v = u64::from(u16::from_be_bytes(self.fixed()?));
                if v <= 0xff {
                    Err(CborError::NonCanonicalInteger)
                } else {
                    Ok(v)
                }
            }
            26 => {
                let v = u64::from(u32::from_be_bytes(self.fixed()?));
                if v <= 0xffff {
                    Err(CborError::NonCanonicalInteger)
                } else {
                    Ok(v)
                }
            }
            27 => {
                let v = u64::from_be_bytes(self.fixed()?);
                if v <= 0xffff_ffff {
                    Err(CborError::NonCanonicalInteger)
                } else {
                    Ok(v)
                }
            }
            28..=30 => Err(CborError::ReservedInfo),
            _ => Err(CborError::IndefiniteLength),
        }
    }

    fn length(&self, arg: u64) -> Result<usize, CborError> {
        let n = usize::try_from(arg).map_err(|_| CborError::TooLarge)?;
        if n > self.limits.max_len {
            return Err(CborError::TooLarge);
        }
        Ok(n)
    }

    fn count(&self, arg: u64) -> Result<usize, CborError> {
        let n = usize::try_from(arg).map_err(|_| CborError::TooManyItems)?;
        if n > self.limits.max_items {
            return Err(CborError::TooManyItems);
        }
        // Every item takes at least one byte: refuse counts the input cannot
        // hold before allocating for them.
        if n > self.buf.len().saturating_sub(self.pos) {
            return Err(CborError::Truncated);
        }
        Ok(n)
    }

    fn value(&mut self, depth: usize) -> Result<Value, CborError> {
        if depth > self.limits.max_depth {
            return Err(CborError::DepthExceeded);
        }
        let initial = self.byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        if major == 7 {
            return self.simple_or_float(info);
        }
        let arg = self.argument(info)?;
        match major {
            0 => Ok(Value::Unsigned(arg)),
            1 => Ok(Value::Negative(arg)),
            2 => {
                let n = self.length(arg)?;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = self.length(arg)?;
                let raw = self.take(n)?;
                let s = core::str::from_utf8(raw).map_err(|_| CborError::InvalidUtf8)?;
                Ok(Value::Text(s.to_owned()))
            }
            4 => {
                let n = self.count(arg)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let n = self.count(arg)?;
                let mut entries = Vec::with_capacity(n);
                let mut previous: Option<&'a [u8]> = None;
                for _ in 0..n {
                    let start = self.pos;
                    let key = self.value(depth + 1)?;
                    let key_bytes = self.buf.get(start..self.pos).ok_or(CborError::Truncated)?;
                    if let Some(prev) = previous {
                        match prev.cmp(key_bytes) {
                            Ordering::Less => {}
                            Ordering::Equal => return Err(CborError::DuplicateMapKey),
                            Ordering::Greater => return Err(CborError::UnsortedMapKeys),
                        }
                    }
                    previous = Some(key_bytes);
                    let value = self.value(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            _ => Err(CborError::UnsupportedTag),
        }
    }

    fn simple_or_float(&mut self, info: u8) -> Result<Value, CborError> {
        match info {
            20 => Ok(Value::Bool(false)),
            21 => Ok(Value::Bool(true)),
            22 => Ok(Value::Null),
            25 => {
                let h = u16::from_be_bytes(self.fixed()?);
                let f = f16_to_f64(h);
                if f.is_nan() && h != 0x7e00 {
                    return Err(CborError::NonCanonicalNaN);
                }
                Ok(Value::Float(f))
            }
            26 => {
                let f = f64::from(f32::from_bits(u32::from_be_bytes(self.fixed()?)));
                if f.is_nan() {
                    return Err(CborError::NonCanonicalNaN);
                }
                if f64_to_f16_exact(f).is_some() {
                    return Err(CborError::NonPreferredFloat);
                }
                Ok(Value::Float(f))
            }
            27 => {
                let f = f64::from_bits(u64::from_be_bytes(self.fixed()?));
                if f.is_nan() {
                    return Err(CborError::NonCanonicalNaN);
                }
                if f64_to_f16_exact(f).is_some() || f64_to_f32_exact(f).is_some() {
                    return Err(CborError::NonPreferredFloat);
                }
                Ok(Value::Float(f))
            }
            28..=30 => Err(CborError::ReservedInfo),
            31 => Err(CborError::IndefiniteLength),
            _ => Err(CborError::UnsupportedSimple),
        }
    }
}

/// RFC 8949 §8 diagnostic notation, for people and logs.
///
/// Text is written with JSON escapes and every non-ASCII character as
/// `\uXXXX` (surrogate pairs above U+FFFF), as in RFC 8949 Appendix A. Float
/// spelling is informative only: conformance compares bytes, not this text.
#[must_use]
pub fn diag(value: &Value) -> String {
    let mut out = String::new();
    diag_into(value, &mut out);
    out
}

fn diag_into(value: &Value, out: &mut String) {
    match value {
        Value::Unsigned(n) => {
            let _ = write!(out, "{n}");
        }
        Value::Negative(n) => {
            let _ = write!(out, "-{}", u128::from(*n) + 1);
        }
        Value::Bytes(b) => {
            out.push_str("h'");
            out.push_str(&crate::hex::encode(b));
            out.push('\'');
        }
        Value::Text(s) => json_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                diag_into(item, out);
            }
            out.push(']');
        }
        Value::Map(entries) => {
            out.push('{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                diag_into(k, out);
                out.push_str(": ");
                diag_into(v, out);
            }
            out.push('}');
        }
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Null => out.push_str("null"),
        Value::Float(f) => {
            if f.is_nan() {
                out.push_str("NaN");
            } else if f.is_infinite() {
                out.push_str(if *f > 0.0 { "Infinity" } else { "-Infinity" });
            } else {
                let _ = write!(out, "{f:?}");
            }
        }
    }
}

fn json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ' '..='~' => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(hex: &str) -> Value {
        let bytes = crate::hex::decode(hex).unwrap();
        let v = decode(&bytes).unwrap();
        assert_eq!(encode(&v).unwrap(), bytes, "re-encoding {hex}");
        v
    }

    #[test]
    fn rfc8949_integers_round_trip() {
        assert_eq!(rt("00"), Value::Unsigned(0));
        assert_eq!(rt("17"), Value::Unsigned(23));
        assert_eq!(rt("1818"), Value::Unsigned(24));
        assert_eq!(rt("1903e8"), Value::Unsigned(1000));
        assert_eq!(rt("1bffffffffffffffff"), Value::Unsigned(u64::MAX));
        assert_eq!(rt("3bffffffffffffffff"), Value::Negative(u64::MAX));
        assert_eq!(diag(&rt("3bffffffffffffffff")), "-18446744073709551616");
    }

    #[test]
    fn rfc8949_floats_are_preferred() {
        for (hex, value) in [
            ("f90000", 0.0),
            ("f93c00", 1.0),
            ("f93e00", 1.5),
            ("f97bff", 65504.0),
            ("fa47c35000", 100_000.0),
            ("fa7f7fffff", 3.402_823_466_385_288_6e38),
            ("fb7e37e43c8800759c", 1.0e300),
            ("f90001", 5.960_464_477_539_063e-8),
            ("f90400", 0.000_061_035_156_25),
            ("f9c400", -4.0),
            ("fbc010666666666666", -4.1),
            ("fb3ff199999999999a", 1.1),
        ] {
            assert_eq!(rt(hex), Value::Float(value), "{hex}");
        }
        assert!(matches!(rt("f97e00"), Value::Float(f) if f.is_nan()));
        assert_eq!(rt("f97c00"), Value::Float(f64::INFINITY));
        let neg_zero = rt("f98000");
        assert!(matches!(neg_zero, Value::Float(f) if f == 0.0 && f.is_sign_negative()));
    }

    #[test]
    fn strictness() {
        let bad = |hex: &str| decode(&crate::hex::decode(hex).unwrap()).unwrap_err();
        assert_eq!(bad("1817"), CborError::NonCanonicalInteger);
        assert_eq!(bad("fa3f800000"), CborError::NonPreferredFloat);
        assert_eq!(bad("fa7fc00000"), CborError::NonCanonicalNaN);
        assert_eq!(bad("f97e01"), CborError::NonCanonicalNaN);
        assert_eq!(bad("9fff"), CborError::IndefiniteLength);
        assert_eq!(bad("c11a514b67b0"), CborError::UnsupportedTag);
        assert_eq!(bad("f7"), CborError::UnsupportedSimple);
        assert_eq!(
            bad("a2030401 02".replace(' ', "").as_str()),
            CborError::UnsortedMapKeys
        );
        assert_eq!(bad("a201020102"), CborError::DuplicateMapKey);
        assert_eq!(bad("62c328"), CborError::InvalidUtf8);
        assert_eq!(bad("0000"), CborError::TrailingBytes);
        assert_eq!(bad("5a00010000"), CborError::Truncated);
        assert_eq!(bad("9b0000000100000000"), CborError::TooManyItems);
    }

    #[test]
    fn encoder_sorts_and_refuses_duplicates() {
        let v = Value::Map(vec![
            (Value::Text("b".into()), Value::Unsigned(2)),
            (Value::Unsigned(10), Value::Unsigned(1)),
            (Value::Text("a".into()), Value::Unsigned(1)),
        ]);
        assert_eq!(
            crate::hex::encode(&encode(&v).unwrap()),
            "a30a01616101616202"
        );
        let dup = Value::Map(vec![
            (Value::Unsigned(1), Value::Null),
            (Value::Unsigned(1), Value::Null),
        ]);
        assert_eq!(encode(&dup).unwrap_err(), CborError::DuplicateMapKey);
    }

    #[test]
    fn depth_is_bounded_both_ways() {
        let mut v = Value::Null;
        for _ in 0..=Limits::DEFAULT.max_depth {
            v = Value::Array(vec![v]);
        }
        assert_eq!(encode(&v).unwrap_err(), CborError::DepthExceeded);
        let deep = [vec![0x81u8; 17], vec![0xf6]].concat();
        assert_eq!(decode(&deep).unwrap_err(), CborError::DepthExceeded);
    }

    #[test]
    fn diagnostic_text_escapes_like_rfc8949() {
        assert_eq!(diag(&Value::Text("\u{fc}".into())), "\"\\u00fc\"");
        assert_eq!(diag(&Value::Text("\u{10151}".into())), "\"\\ud800\\udd51\"");
        assert_eq!(diag(&rt("8301820203820405")), "[1, [2, 3], [4, 5]]");
    }
}
