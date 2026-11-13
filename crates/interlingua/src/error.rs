//! Errors and routing reasons.
//!
//! Every failure has a stable numeric code and a stable name. The C ABI returns
//! the code, the conformance vectors name the error (`Cbor/NonPreferredFloat`,
//! `BadSignature`, …), and every language binding compares those names, so a
//! name never changes meaning once released (see `docs/SPECIFICATION.md` §9).

use core::fmt;

/// A CBOR input that is not well-formed, or well-formed but not in the
/// deterministic form interlingua accepts (RFC 8949 §4.2.1 plus the stricter
/// rules in `docs/SPECIFICATION.md` §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CborError {
    /// The input ended inside an item.
    Truncated,
    /// Bytes remain after the single top-level item.
    TrailingBytes,
    /// An integer, length or count was not in its shortest form.
    NonCanonicalInteger,
    /// An indefinite-length item (forbidden in deterministic encoding).
    IndefiniteLength,
    /// Additional-information values 28–30 (reserved by RFC 8949).
    ReservedInfo,
    /// A tag (major type 6); interlingua's data model has no tags.
    UnsupportedTag,
    /// A simple value other than false, true or null, or `undefined`.
    UnsupportedSimple,
    /// A float that a shorter IEEE 754 width represents exactly.
    NonPreferredFloat,
    /// A NaN other than the canonical half-precision `0xf97e00`.
    NonCanonicalNaN,
    /// Map keys not in bytewise lexicographic order of their encodings.
    UnsortedMapKeys,
    /// The same map key twice.
    DuplicateMapKey,
    /// A text string that is not valid UTF-8.
    InvalidUtf8,
    /// Nesting deeper than the decoder's limit.
    DepthExceeded,
    /// An array or map with more items than the decoder's limit.
    TooManyItems,
    /// An input or string longer than the decoder's limit.
    TooLarge,
}

impl CborError {
    /// The stable name used by the conformance vectors.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Truncated => "Truncated",
            Self::TrailingBytes => "TrailingBytes",
            Self::NonCanonicalInteger => "NonCanonicalInteger",
            Self::IndefiniteLength => "IndefiniteLength",
            Self::ReservedInfo => "ReservedInfo",
            Self::UnsupportedTag => "UnsupportedTag",
            Self::UnsupportedSimple => "UnsupportedSimple",
            Self::NonPreferredFloat => "NonPreferredFloat",
            Self::NonCanonicalNaN => "NonCanonicalNaN",
            Self::UnsortedMapKeys => "UnsortedMapKeys",
            Self::DuplicateMapKey => "DuplicateMapKey",
            Self::InvalidUtf8 => "InvalidUtf8",
            Self::DepthExceeded => "DepthExceeded",
            Self::TooManyItems => "TooManyItems",
            Self::TooLarge => "TooLarge",
        }
    }
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Every error the library reports.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An argument was out of range or otherwise unusable.
    InvalidArgument(&'static str),
    /// Malformed or non-canonical CBOR.
    Cbor(CborError),
    /// Well-formed CBOR with the wrong structure for an interlingua object.
    Schema(&'static str),
    /// A wire-format version this library does not implement.
    Version(u64),
    /// An algorithm suite this library does not implement.
    Suite(u64),
    /// A domain name, compartment or media type that breaks the syntax rules.
    Identifier(&'static str),
    /// A security label that breaks the label rules.
    Label(&'static str),
    /// A cryptographic primitive failed (random generator, key generation, …).
    Crypto(&'static str),
    /// The signature does not verify.
    BadSignature,
    /// The signing key is not in the keyring.
    UnknownSigner,
    /// The signing key is in the keyring but bound to a different domain.
    SignerNotAuthorized,
    /// Decapsulation or authenticated decryption failed.
    Decrypt,
    /// The payload is sealed to a different recipient key.
    WrongRecipient,
    /// The payload is sealed and no decapsulation key was supplied.
    KeyRequired,
    /// A key or key bundle could not be parsed or is the wrong size.
    Key(&'static str),
    /// A routing policy failed to parse or validate.
    Policy {
        /// 1-based line number (0 when the problem spans the whole policy).
        line: usize,
        /// What is wrong.
        message: String,
    },
    /// A CCSDS Space Packet is malformed or out of sequence.
    Ccsds(&'static str),
    /// A conformance vector failed to parse or did not match.
    Vector(String),
}

impl Error {
    /// Stable numeric code (negative, as returned by the C ABI).
    #[must_use]
    pub const fn code(&self) -> i32 {
        match self {
            Self::InvalidArgument(_) => -1,
            Self::Cbor(_) => -10,
            Self::Schema(_) => -11,
            Self::Version(_) => -12,
            Self::Suite(_) => -13,
            Self::Identifier(_) => -20,
            Self::Label(_) => -21,
            Self::Crypto(_) => -30,
            Self::BadSignature => -31,
            Self::UnknownSigner => -32,
            Self::SignerNotAuthorized => -33,
            Self::Decrypt => -34,
            Self::WrongRecipient => -35,
            Self::KeyRequired => -36,
            Self::Key(_) => -40,
            Self::Policy { .. } => -50,
            Self::Ccsds(_) => -60,
            Self::Vector(_) => -70,
        }
    }

    /// Stable name of the error class.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::InvalidArgument(_) => "InvalidArgument",
            Self::Cbor(_) => "Cbor",
            Self::Schema(_) => "Schema",
            Self::Version(_) => "Version",
            Self::Suite(_) => "Suite",
            Self::Identifier(_) => "Identifier",
            Self::Label(_) => "Label",
            Self::Crypto(_) => "Crypto",
            Self::BadSignature => "BadSignature",
            Self::UnknownSigner => "UnknownSigner",
            Self::SignerNotAuthorized => "SignerNotAuthorized",
            Self::Decrypt => "Decrypt",
            Self::WrongRecipient => "WrongRecipient",
            Self::KeyRequired => "KeyRequired",
            Self::Key(_) => "Key",
            Self::Policy { .. } => "Policy",
            Self::Ccsds(_) => "Ccsds",
            Self::Vector(_) => "Vector",
        }
    }

    /// The identifier the conformance vectors compare: the class name, plus the
    /// CBOR detail for CBOR errors (`Cbor/NonPreferredFloat`).
    #[must_use]
    pub fn id(&self) -> String {
        match self {
            Self::Cbor(detail) => format!("Cbor/{}", detail.name()),
            other => other.name().to_owned(),
        }
    }

    /// Name of the class behind a numeric code (`"Unknown"` for anything else).
    #[must_use]
    pub const fn name_for_code(code: i32) -> &'static str {
        match code {
            0 => "Ok",
            -1 => "InvalidArgument",
            -10 => "Cbor",
            -11 => "Schema",
            -12 => "Version",
            -13 => "Suite",
            -20 => "Identifier",
            -21 => "Label",
            -30 => "Crypto",
            -31 => "BadSignature",
            -32 => "UnknownSigner",
            -33 => "SignerNotAuthorized",
            -34 => "Decrypt",
            -35 => "WrongRecipient",
            -36 => "KeyRequired",
            -40 => "Key",
            -50 => "Policy",
            -60 => "Ccsds",
            -70 => "Vector",
            -99 => "Panic",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
            Self::Cbor(e) => write!(f, "CBOR rejected: {e}"),
            Self::Schema(m) => write!(f, "schema violation: {m}"),
            Self::Version(v) => write!(f, "unsupported format version {v}"),
            Self::Suite(s) => write!(f, "unsupported algorithm suite {s}"),
            Self::Identifier(m) => write!(f, "invalid identifier: {m}"),
            Self::Label(m) => write!(f, "invalid label: {m}"),
            Self::Crypto(m) => write!(f, "cryptographic failure: {m}"),
            Self::BadSignature => f.write_str("signature does not verify"),
            Self::UnknownSigner => f.write_str("signing key is not in the keyring"),
            Self::SignerNotAuthorized => {
                f.write_str("signing key is not bound to the source domain")
            }
            Self::Decrypt => f.write_str("decapsulation or authenticated decryption failed"),
            Self::WrongRecipient => f.write_str("payload is sealed to a different recipient"),
            Self::KeyRequired => f.write_str("payload is sealed; a decapsulation key is required"),
            Self::Key(m) => write!(f, "key error: {m}"),
            Self::Policy { line: 0, message } => write!(f, "policy: {message}"),
            Self::Policy { line, message } => write!(f, "policy line {line}: {message}"),
            Self::Ccsds(m) => write!(f, "CCSDS space packet: {m}"),
            Self::Vector(m) => write!(f, "conformance vector: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<CborError> for Error {
    fn from(e: CborError) -> Self {
        Self::Cbor(e)
    }
}

/// Why the router refused a message. Codes 100–199 are reserved for reasons;
/// `0` means "accepted" in the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Reason {
    /// The envelope did not decode (CBOR, schema, version or suite).
    Malformed,
    /// The source domain is not in the policy.
    UnknownSourceDomain,
    /// The destination domain is not in the policy.
    UnknownDestinationDomain,
    /// The signing key is not in the router's keyring.
    UnknownSigner,
    /// The signing key belongs to a domain other than the stated source.
    SignerNotAuthorized,
    /// The signature does not verify.
    BadSignature,
    /// The message is past its expiry time.
    Expired,
    /// The message claims a creation time beyond the allowed clock skew.
    NotYetValid,
    /// Expiry minus creation exceeds the policy's maximum lifetime.
    LifetimeTooLong,
    /// No forwarding hops remain, or the route needs more hops than remain.
    HopLimitExceeded,
    /// The unprotected hop count is above the signed maximum.
    HopCountInflated,
    /// This router has already accepted a message with this identifier.
    Replay,
    /// No path permits this label, size and sealing state.
    NoRoute,
    /// The message arrived over an edge the policy does not allow for it.
    UnexpectedArrival,
    /// The label's confidentiality is above what the source may originate.
    ConfidentialityExceedsSource,
    /// The label's confidentiality is above the destination's clearance.
    ConfidentialityExceedsDestination,
    /// The label's integrity is above what the source can vouch for.
    IntegrityExceedsSource,
    /// The label's integrity is below the destination's integrity floor.
    IntegrityBelowFloor,
    /// A compartment the source or destination may not hold.
    CompartmentNotPermitted,
    /// Policy requires a sealed payload and this one is plaintext.
    EncryptionRequired,
    /// The payload is sealed to a key that is not the destination's.
    SealedToWrongRecipient,
    /// The envelope is larger than any permitted edge allows.
    PayloadTooLarge,
    /// The source domain exceeded its rate allowance at this router.
    RateLimited,
    /// The replay cache is full of unexpired entries.
    Overloaded,
}

impl Reason {
    /// Stable numeric code (100–199).
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Malformed => 100,
            Self::UnknownSourceDomain => 101,
            Self::UnknownDestinationDomain => 102,
            Self::UnknownSigner => 103,
            Self::SignerNotAuthorized => 104,
            Self::BadSignature => 105,
            Self::Expired => 106,
            Self::NotYetValid => 107,
            Self::LifetimeTooLong => 108,
            Self::HopLimitExceeded => 109,
            Self::HopCountInflated => 110,
            Self::Replay => 111,
            Self::NoRoute => 112,
            Self::UnexpectedArrival => 113,
            Self::ConfidentialityExceedsSource => 114,
            Self::ConfidentialityExceedsDestination => 115,
            Self::IntegrityExceedsSource => 116,
            Self::IntegrityBelowFloor => 117,
            Self::CompartmentNotPermitted => 118,
            Self::EncryptionRequired => 119,
            Self::SealedToWrongRecipient => 120,
            Self::PayloadTooLarge => 121,
            Self::RateLimited => 122,
            Self::Overloaded => 123,
        }
    }

    /// Stable name used in the audit trail and the conformance vectors.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Malformed => "Malformed",
            Self::UnknownSourceDomain => "UnknownSourceDomain",
            Self::UnknownDestinationDomain => "UnknownDestinationDomain",
            Self::UnknownSigner => "UnknownSigner",
            Self::SignerNotAuthorized => "SignerNotAuthorized",
            Self::BadSignature => "BadSignature",
            Self::Expired => "Expired",
            Self::NotYetValid => "NotYetValid",
            Self::LifetimeTooLong => "LifetimeTooLong",
            Self::HopLimitExceeded => "HopLimitExceeded",
            Self::HopCountInflated => "HopCountInflated",
            Self::Replay => "Replay",
            Self::NoRoute => "NoRoute",
            Self::UnexpectedArrival => "UnexpectedArrival",
            Self::ConfidentialityExceedsSource => "ConfidentialityExceedsSource",
            Self::ConfidentialityExceedsDestination => "ConfidentialityExceedsDestination",
            Self::IntegrityExceedsSource => "IntegrityExceedsSource",
            Self::IntegrityBelowFloor => "IntegrityBelowFloor",
            Self::CompartmentNotPermitted => "CompartmentNotPermitted",
            Self::EncryptionRequired => "EncryptionRequired",
            Self::SealedToWrongRecipient => "SealedToWrongRecipient",
            Self::PayloadTooLarge => "PayloadTooLarge",
            Self::RateLimited => "RateLimited",
            Self::Overloaded => "Overloaded",
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
