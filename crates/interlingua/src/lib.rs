//! # interlingua
//!
//! A security-first, polyglot message fabric: one canonical message format
//! that every language reads and writes identically, a deny-by-default
//! router between labelled trust domains, and CCSDS space-packet framing.
//!
//! * **One canonical form.** Envelopes are strict deterministic CBOR
//!   ([`cbor`]): one encoding per value, so a signature means the same
//!   thing in Rust, C, Swift, Go and Java.
//! * **CNSA 2.0 cryptography** ([`crypto`]): ML-DSA-87 signatures, ML-KEM-1024
//!   key establishment, HKDF-SHA-384 and AES-256-GCM, from AWS-LC (FIPS 140-3
//!   module available with the `fips` feature).
//! * **Labels** ([`label`]): FIPS 199 confidentiality / integrity /
//!   availability impacts plus compartments on every message.
//! * **Routing** ([`router`], [`policy`]): Bell–LaPadula and Biba rules,
//!   sealing requirements, replay and rate limits, shortest permitted path,
//!   and a hash-chained [`audit`] trail.
//! * **Space links** ([`ccsds`]): CCSDS 133.0-B-2 Space Packets.
//!
//! The library has no clock, network or file I/O: callers pass the time and
//! the bytes, so every decision is reproducible in tests and audits.
//!
//! ```
//! use interlingua::{Draft, Keyring, Label, SecretKeys, envelope::seal_and_sign};
//!
//! let ground = SecretKeys::generate("ground-ops")?;
//! let craft = SecretKeys::generate("space-segment")?;
//! let mut ring = Keyring::new();
//! ring.add(ground.public())?;
//! ring.add(craft.public())?;
//!
//! let draft = Draft {
//!     src: "ground-ops",
//!     dst: "space-segment",
//!     label: Label::parse("conf=moderate integ=high avail=high comp=tt-c")?,
//!     content_type: "application/octet-stream",
//!     ttl_ms: 60_000,
//!     max_hops: 4,
//!     payload: b"SAFE MODE EXIT",
//! };
//! let now_ms = 1_767_225_600_000;
//! let wire = seal_and_sign(&draft, &ground.signing, Some(craft.decapsulation.encapsulation_key()), now_ms)?
//!     .encode()?;
//!
//! let received = interlingua::Envelope::decode(&wire)?;
//! assert_eq!(received.verify_and_open(&ring, Some(&craft.decapsulation))?, b"SAFE MODE EXIT");
//! # Ok::<(), interlingua::Error>(())
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[cfg(not(any(feature = "fips", feature = "non-fips")))]
compile_error!("enable a crypto backend: the `non-fips` feature (default) or `fips`");

pub mod audit;
pub mod cbor;
pub mod ccsds;
pub mod crypto;
pub mod envelope;
pub mod error;
pub mod hex;
pub mod ident;
pub mod keys;
pub mod label;
pub mod policy;
pub mod router;
pub mod uuid7;
pub mod vectors;

pub use envelope::{Draft, Envelope, Header};
pub use error::{CborError, Error, Reason};
pub use keys::{Keyring, PublicKeys, SecretKeys};
pub use label::{Impact, Label};
pub use policy::Policy;
pub use router::{Decision, Router, Verdict};

/// Wire-format version this library writes and accepts.
pub const FORMAT_VERSION: u64 = 1;

/// Algorithm suite 1, `IL1-CNSA2`: ML-DSA-87, ML-KEM-1024, HKDF-SHA-384,
/// AES-256-GCM, SHA-384.
pub const SUITE_IL1_CNSA2: u64 = 1;

/// This library's version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Whether this build uses the AWS-LC FIPS 140-3 module.
#[must_use]
pub const fn fips_build() -> bool {
    cfg!(feature = "fips")
}
