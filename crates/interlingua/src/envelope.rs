//! The interlingua envelope (wire format version 1, suite IL1-CNSA2).
//!
//! ```text
//! envelope    = [protected: bstr, unprotected: {1: hops}, payload: bstr, signature: bstr]
//! protected   = deterministic CBOR of the header map (keys 1-12, see Header)
//! signature   = ML-DSA-87 over  ["IL1-Sign", protected, payload]
//! sealed payload = [recipient-key-id: bstr(48), kem-ciphertext: bstr(1568), aead: bstr]
//! ```
//!
//! The header is signed exactly as transmitted; the hop count is the one
//! field a router may change, so it sits outside the signature and can never
//! rise above the signed `max_hops`. When the payload is sealed, the AES-256-GCM
//! key and nonce come from HKDF-SHA-384 over the ML-KEM-1024 shared secret
//! with the SHA-384 of the protected header as salt, and the protected header
//! is also the AEAD's associated data: a sealed payload cannot be moved under
//! another header. The normative text is `docs/SPECIFICATION.md`.

use zeroize::Zeroizing;

use crate::cbor::{self, Value};
use crate::crypto::{self, DecapsulationKey, KEY_ID_LEN, SigningKey};
use crate::error::Error;
use crate::keys::{Keyring, PublicKeys};
use crate::label::Label;
use crate::{FORMAT_VERSION, SUITE_IL1_CNSA2, ident, uuid7};

/// Most forwarding hops an envelope may allow.
pub const MAX_HOPS: u8 = 64;
const SIGN_CONTEXT: &str = "IL1-Sign";
const ENCRYPT_CONTEXT: &str = "IL1-Encrypt";
const SEAL_INFO: &[u8] = b"IL1-Seal-AES256GCM";

/// The signed header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Key 1: wire-format version (1).
    pub version: u64,
    /// Key 2: algorithm suite (1 = IL1-CNSA2).
    pub suite: u64,
    /// Key 3: message identifier (UUIDv7).
    pub id: [u8; uuid7::LEN],
    /// Key 4: source domain.
    pub src: String,
    /// Key 5: destination domain.
    pub dst: String,
    /// Key 6: security label.
    pub label: Label,
    /// Key 7: creation time, Unix milliseconds.
    pub created_ms: u64,
    /// Key 8: expiry time, Unix milliseconds.
    pub expires_ms: u64,
    /// Key 9: most forwarding hops allowed.
    pub max_hops: u8,
    /// Key 10: payload media type.
    pub content_type: String,
    /// Key 11: whether the payload is sealed.
    pub sealed: bool,
    /// Key 12: SHA-384 identifier of the signing key.
    pub signer: [u8; KEY_ID_LEN],
}

impl Header {
    /// The header as a CBOR map.
    #[must_use]
    pub fn to_cbor(&self) -> Value {
        let u = Value::Unsigned;
        Value::Map(vec![
            (u(1), u(self.version)),
            (u(2), u(self.suite)),
            (u(3), Value::Bytes(self.id.to_vec())),
            (u(4), Value::Text(self.src.clone())),
            (u(5), Value::Text(self.dst.clone())),
            (u(6), self.label.to_cbor()),
            (u(7), u(self.created_ms)),
            (u(8), u(self.expires_ms)),
            (u(9), u(u64::from(self.max_hops))),
            (u(10), Value::Text(self.content_type.clone())),
            (u(11), Value::Bool(self.sealed)),
            (u(12), Value::Bytes(self.signer.to_vec())),
        ])
    }

    /// Parse and validate a header map.
    ///
    /// # Errors
    /// [`Error::Version`] or [`Error::Suite`] for unknown versions or suites,
    /// otherwise [`Error::Schema`], [`Error::Identifier`] or [`Error::Label`].
    pub fn from_cbor(value: &Value) -> Result<Self, Error> {
        let entries = value
            .as_map()
            .ok_or(Error::Schema("header must be a map"))?;
        // Version first, so a future version is reported as such rather than as
        // a schema mismatch.
        let version = match entries.first() {
            Some((Value::Unsigned(1), Value::Unsigned(v))) => *v,
            _ => {
                return Err(Error::Schema(
                    "header key 1 (version) must be an unsigned integer",
                ));
            }
        };
        if version != FORMAT_VERSION {
            return Err(Error::Version(version));
        }
        if entries.len() != 12
            || entries
                .iter()
                .zip(1u64..)
                .any(|((k, _), want)| k.as_u64() != Some(want))
        {
            return Err(Error::Schema("header must have exactly keys 1 to 12"));
        }
        let get = |k: usize| {
            entries
                .get(k - 1)
                .map(|(_, v)| v)
                .ok_or(Error::Schema("header field missing"))
        };
        let uint = |k: usize, what: &'static str| get(k)?.as_u64().ok_or(Error::Schema(what));
        let text = |k: usize, what: &'static str| {
            get(k)?
                .as_text()
                .map(str::to_owned)
                .ok_or(Error::Schema(what))
        };
        let bytes = |k: usize, what: &'static str| get(k)?.as_bytes().ok_or(Error::Schema(what));

        let suite = uint(2, "suite must be an unsigned integer")?;
        if suite != SUITE_IL1_CNSA2 {
            return Err(Error::Suite(suite));
        }
        let id: [u8; uuid7::LEN] = bytes(3, "id must be a byte string")?
            .try_into()
            .map_err(|_| Error::Schema("id must be 16 bytes"))?;
        if !uuid7::is_v7(&id) {
            return Err(Error::Schema("id must be a UUIDv7"));
        }
        let src = text(4, "src must be text")?;
        let dst = text(5, "dst must be text")?;
        ident::domain(&src)?;
        ident::domain(&dst)?;
        let label = Label::from_cbor(get(6)?)?;
        let created_ms = uint(7, "created must be an unsigned integer")?;
        let expires_ms = uint(8, "expires must be an unsigned integer")?;
        if expires_ms <= created_ms {
            return Err(Error::Schema("expires must be after created"));
        }
        let max_hops = u8::try_from(uint(9, "max_hops must be an unsigned integer")?)
            .ok()
            .filter(|h| (1..=MAX_HOPS).contains(h))
            .ok_or(Error::Schema("max_hops must be 1-64"))?;
        let content_type = text(10, "content type must be text")?;
        ident::content_type(&content_type)?;
        let sealed = get(11)?
            .as_bool()
            .ok_or(Error::Schema("sealed must be a boolean"))?;
        let signer: [u8; KEY_ID_LEN] = bytes(12, "signer must be a byte string")?
            .try_into()
            .map_err(|_| Error::Schema("signer key id must be 48 bytes"))?;
        Ok(Self {
            version,
            suite,
            id,
            src,
            dst,
            label,
            created_ms,
            expires_ms,
            max_hops,
            content_type,
            sealed,
            signer,
        })
    }
}

/// What a sender wants to send.
#[derive(Debug, Clone)]
pub struct Draft<'a> {
    /// Source domain (must be the signing key's domain).
    pub src: &'a str,
    /// Destination domain.
    pub dst: &'a str,
    /// Security label.
    pub label: Label,
    /// Payload media type.
    pub content_type: &'a str,
    /// Lifetime from now, in milliseconds.
    pub ttl_ms: u64,
    /// Most forwarding hops.
    pub max_hops: u8,
    /// Payload bytes.
    pub payload: &'a [u8],
}

/// Intermediate values of one sealing, for cross-implementation test vectors.
#[derive(Debug, Clone)]
pub struct SealTrace {
    /// ML-KEM-1024 shared secret.
    pub shared_secret: [u8; crypto::SHARED_SECRET_LEN],
    /// Derived AES-256 key.
    pub key: [u8; crypto::AES256_KEY_LEN],
    /// Derived GCM nonce.
    pub nonce: [u8; crypto::GCM_NONCE_LEN],
    /// AEAD associated data.
    pub aad: Vec<u8>,
}

/// A decoded envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The protected header bytes exactly as signed.
    pub protected: Vec<u8>,
    /// The parsed header.
    pub header: Header,
    /// Forwarding hops remaining (unprotected).
    pub hops: u8,
    /// Payload: plaintext, or the sealed structure when `header.sealed`.
    pub payload: Vec<u8>,
    /// ML-DSA-87 signature.
    pub signature: Vec<u8>,
}

fn sig_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(cbor::encode(&Value::Array(vec![
        Value::Text(SIGN_CONTEXT.into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(payload.to_vec()),
    ]))?)
}

fn enc_structure(protected: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(cbor::encode(&Value::Array(vec![
        Value::Text(ENCRYPT_CONTEXT.into()),
        Value::Bytes(protected.to_vec()),
    ]))?)
}

fn seal_keys(
    shared_secret: &[u8],
    protected: &[u8],
    recipient: &[u8; KEY_ID_LEN],
) -> Result<(Zeroizing<[u8; 32]>, [u8; 12]), Error> {
    let mut okm = Zeroizing::new([0u8; 44]);
    let info = [SEAL_INFO, recipient.as_slice()].concat();
    crypto::hkdf_sha384(
        shared_secret,
        &crypto::sha384(protected),
        &info,
        okm.as_mut_slice(),
    )?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&okm[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&okm[32..]);
    Ok((key, nonce))
}

/// The three parts of a sealed payload.
struct SealedParts {
    recipient: [u8; KEY_ID_LEN],
    kem_ciphertext: Vec<u8>,
    aead: Vec<u8>,
}

fn split_sealed(payload: &[u8]) -> Result<SealedParts, Error> {
    let bad = Error::Schema("sealed payload must be [key id (48), ciphertext (1568), aead]");
    let value = cbor::decode(payload).map_err(|_| bad.clone())?;
    match value {
        Value::Array(items) => match <[Value; 3]>::try_from(items) {
            Ok(
                [
                    Value::Bytes(kid),
                    Value::Bytes(kem_ciphertext),
                    Value::Bytes(aead),
                ],
            ) if kem_ciphertext.len() == crypto::MLKEM1024_CIPHERTEXT_LEN
                && aead.len() >= crypto::GCM_TAG_LEN =>
            {
                let recipient: [u8; KEY_ID_LEN] = kid.try_into().map_err(|_| bad.clone())?;
                Ok(SealedParts {
                    recipient,
                    kem_ciphertext,
                    aead,
                })
            }
            _ => Err(bad),
        },
        _ => Err(bad),
    }
}

/// Build, optionally seal, and sign an envelope.
///
/// `recipient_ek` is the destination's ML-KEM-1024 encapsulation key; `None`
/// sends plaintext. `now_ms` is the creation time (the library has no clock).
///
/// # Errors
/// [`Error::InvalidArgument`], [`Error::Identifier`], [`Error::Key`] or
/// [`Error::Crypto`].
pub fn seal_and_sign(
    draft: &Draft<'_>,
    signer: &SigningKey,
    recipient_ek: Option<&[u8]>,
    now_ms: u64,
) -> Result<Envelope, Error> {
    seal_and_sign_traced(draft, signer, recipient_ek, now_ms).map(|(env, _)| env)
}

/// [`seal_and_sign`], also returning the sealing intermediates. Only test-vector
/// generation needs these; they are secret for real traffic.
///
/// # Errors
/// As [`seal_and_sign`].
#[doc(hidden)]
pub fn seal_and_sign_traced(
    draft: &Draft<'_>,
    signer: &SigningKey,
    recipient_ek: Option<&[u8]>,
    now_ms: u64,
) -> Result<(Envelope, Option<SealTrace>), Error> {
    ident::domain(draft.src)?;
    ident::domain(draft.dst)?;
    ident::content_type(draft.content_type)?;
    if !(1..=MAX_HOPS).contains(&draft.max_hops) {
        return Err(Error::InvalidArgument("max_hops must be 1-64"));
    }
    if draft.ttl_ms == 0 {
        return Err(Error::InvalidArgument("ttl must be positive"));
    }
    let expires_ms = now_ms
        .checked_add(draft.ttl_ms)
        .ok_or(Error::InvalidArgument("expiry overflows"))?;
    let header = Header {
        version: FORMAT_VERSION,
        suite: SUITE_IL1_CNSA2,
        id: uuid7::new_v7(now_ms)?,
        src: draft.src.to_owned(),
        dst: draft.dst.to_owned(),
        label: draft.label.clone(),
        created_ms: now_ms,
        expires_ms,
        max_hops: draft.max_hops,
        content_type: draft.content_type.to_owned(),
        sealed: recipient_ek.is_some(),
        signer: signer.key_id(),
    };
    let protected = cbor::encode(&header.to_cbor())?;
    let (payload, trace) = match recipient_ek {
        None => (draft.payload.to_vec(), None),
        Some(ek) => {
            let recipient = crypto::key_id(ek);
            let (kem_ct, shared_secret) = crypto::encapsulate(ek)?;
            let (key, nonce) = seal_keys(shared_secret.as_slice(), &protected, &recipient)?;
            let aad = enc_structure(&protected)?;
            let aead = crypto::aes256gcm_seal(&key, &nonce, &aad, draft.payload)?;
            let sealed = cbor::encode(&Value::Array(vec![
                Value::Bytes(recipient.to_vec()),
                Value::Bytes(kem_ct),
                Value::Bytes(aead),
            ]))?;
            let trace = SealTrace {
                shared_secret: *shared_secret,
                key: *key,
                nonce,
                aad,
            };
            (sealed, Some(trace))
        }
    };
    let signature = signer.sign(&sig_structure(&protected, &payload)?)?;
    Ok((
        Envelope {
            protected,
            header,
            hops: draft.max_hops,
            payload,
            signature,
        },
        trace,
    ))
}

impl Envelope {
    /// The wire encoding.
    ///
    /// # Errors
    /// [`Error::Cbor`] only if the envelope exceeds the size limits.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(cbor::encode(&Value::Array(vec![
            Value::Bytes(self.protected.clone()),
            Value::Map(vec![(
                Value::Unsigned(1),
                Value::Unsigned(u64::from(self.hops)),
            )]),
            Value::Bytes(self.payload.clone()),
            Value::Bytes(self.signature.clone()),
        ]))?)
    }

    /// Decode and structurally validate an envelope. This does not verify the
    /// signature: call [`Envelope::verify`].
    ///
    /// # Errors
    /// [`Error::Cbor`], [`Error::Schema`], [`Error::Version`], [`Error::Suite`],
    /// [`Error::Identifier`] or [`Error::Label`].
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let value = cbor::decode(bytes)?;
        let Value::Array(items) = value else {
            return Err(Error::Schema("envelope must be an array"));
        };
        let Ok([protected, unprotected, payload, signature]) = <[Value; 4]>::try_from(items) else {
            return Err(Error::Schema("envelope must have four elements"));
        };
        let Value::Bytes(protected) = protected else {
            return Err(Error::Schema("protected header must be a byte string"));
        };
        let header = Header::from_cbor(&cbor::decode(&protected)?)?;
        let hops = match unprotected.as_map() {
            Some([(Value::Unsigned(1), Value::Unsigned(h))]) => {
                u8::try_from(*h).map_err(|_| Error::Schema("hops must be 0-255"))?
            }
            _ => {
                return Err(Error::Schema(
                    "unprotected header must be exactly {1: hops}",
                ));
            }
        };
        let Value::Bytes(payload) = payload else {
            return Err(Error::Schema("payload must be a byte string"));
        };
        let Value::Bytes(signature) = signature else {
            return Err(Error::Schema("signature must be a byte string"));
        };
        if signature.len() != crypto::MLDSA87_SIGNATURE_LEN {
            return Err(Error::Schema("signature must be 4627 bytes"));
        }
        if header.sealed {
            split_sealed(&payload)?;
        }
        Ok(Self {
            protected,
            header,
            hops,
            payload,
            signature,
        })
    }

    /// Verify the signature with the keyring: the signer must be known and
    /// bound to the source domain. Returns the signer's public keys.
    ///
    /// # Errors
    /// [`Error::UnknownSigner`], [`Error::SignerNotAuthorized`] or
    /// [`Error::BadSignature`].
    pub fn verify<'k>(&self, keyring: &'k Keyring) -> Result<&'k PublicKeys, Error> {
        let signer = keyring
            .signer(&self.header.signer)
            .ok_or(Error::UnknownSigner)?;
        if signer.domain != self.header.src {
            return Err(Error::SignerNotAuthorized);
        }
        self.verify_with(&signer.verifying_key)?;
        Ok(signer)
    }

    /// Verify the signature against one raw ML-DSA-87 public key.
    ///
    /// # Errors
    /// [`Error::UnknownSigner`] if the key's identifier does not match the
    /// header, [`Error::BadSignature`] otherwise.
    pub fn verify_with(&self, verifying_key: &[u8]) -> Result<(), Error> {
        if crypto::key_id(verifying_key) != self.header.signer {
            return Err(Error::UnknownSigner);
        }
        crypto::verify(
            verifying_key,
            &sig_structure(&self.protected, &self.payload)?,
            &self.signature,
        )
    }

    /// The bytes the signature covers, for verification with other FIPS 204
    /// implementations.
    ///
    /// # Errors
    /// [`Error::Cbor`] only if the envelope exceeds the size limits.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, Error> {
        sig_structure(&self.protected, &self.payload)
    }

    /// The recipient key identifier of a sealed payload.
    ///
    /// # Errors
    /// [`Error::Schema`] if the payload is not sealed or malformed.
    pub fn sealed_recipient(&self) -> Result<[u8; KEY_ID_LEN], Error> {
        if !self.header.sealed {
            return Err(Error::Schema("payload is not sealed"));
        }
        split_sealed(&self.payload).map(|parts| parts.recipient)
    }

    /// The plaintext payload. Plaintext envelopes need no key; sealed ones need
    /// the destination's decapsulation key. Does not verify the signature.
    ///
    /// # Errors
    /// [`Error::KeyRequired`], [`Error::WrongRecipient`] or [`Error::Decrypt`].
    pub fn open(&self, dk: Option<&DecapsulationKey>) -> Result<Vec<u8>, Error> {
        if !self.header.sealed {
            return Ok(self.payload.clone());
        }
        let dk = dk.ok_or(Error::KeyRequired)?;
        let parts = split_sealed(&self.payload)?;
        if parts.recipient != dk.key_id() {
            return Err(Error::WrongRecipient);
        }
        let shared_secret = dk.decapsulate(&parts.kem_ciphertext)?;
        let (key, nonce) = seal_keys(shared_secret.as_slice(), &self.protected, &parts.recipient)?;
        crypto::aes256gcm_open(&key, &nonce, &enc_structure(&self.protected)?, &parts.aead)
    }

    /// [`Envelope::verify`] then [`Envelope::open`].
    ///
    /// # Errors
    /// Any error of the two steps.
    pub fn verify_and_open(
        &self,
        keyring: &Keyring,
        dk: Option<&DecapsulationKey>,
    ) -> Result<Vec<u8>, Error> {
        self.verify(keyring)?;
        self.open(dk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SecretKeys;

    fn draft(payload: &[u8]) -> Draft<'_> {
        Draft {
            src: "ground-ops",
            dst: "space-segment",
            label: Label::parse("conf=moderate integ=high avail=moderate comp=tt-c").unwrap(),
            content_type: "application/octet-stream",
            ttl_ms: 60_000,
            max_hops: 4,
            payload,
        }
    }

    #[test]
    fn sealed_round_trip_and_tamper_detection() {
        let ground = SecretKeys::generate("ground-ops").unwrap();
        let space = SecretKeys::generate("space-segment").unwrap();
        let mut ring = Keyring::new();
        ring.add(ground.public()).unwrap();
        ring.add(space.public()).unwrap();

        let env = seal_and_sign(
            &draft(b"ARM PAYLOAD BAY"),
            &ground.signing,
            Some(space.decapsulation.encapsulation_key()),
            1_767_225_600_000,
        )
        .unwrap();
        let wire = env.encode().unwrap();
        let back = Envelope::decode(&wire).unwrap();
        assert_eq!(back, env);
        assert_eq!(
            back.verify_and_open(&ring, Some(&space.decapsulation))
                .unwrap(),
            b"ARM PAYLOAD BAY"
        );
        assert_eq!(
            back.open(Some(&ground.decapsulation)),
            Err(Error::WrongRecipient)
        );
        assert_eq!(back.open(None), Err(Error::KeyRequired));

        // Flip one bit anywhere in the signed region: verification fails.
        for index in [5, wire.len() / 2, wire.len() - 1] {
            let mut bad = wire.clone();
            bad[index] ^= 0x01;
            let verdict = Envelope::decode(&bad).and_then(|e| e.verify(&ring).map(|_| ()));
            assert!(verdict.is_err(), "bit flip at {index} went unnoticed");
        }
    }

    #[test]
    fn hop_count_is_outside_the_signature() {
        let ground = SecretKeys::generate("ground-ops").unwrap();
        let mut ring = Keyring::new();
        ring.add(ground.public()).unwrap();
        let mut env =
            seal_and_sign(&draft(b"hello"), &ground.signing, None, 1_767_225_600_000).unwrap();
        env.hops -= 1;
        let back = Envelope::decode(&env.encode().unwrap()).unwrap();
        back.verify(&ring).unwrap();
        assert_eq!(back.open(None).unwrap(), b"hello");
    }

    #[test]
    fn signer_must_own_the_source_domain() {
        let ground = SecretKeys::generate("ground-ops").unwrap();
        let mallory = SecretKeys::generate("mallory").unwrap();
        let mut ring = Keyring::new();
        ring.add(ground.public()).unwrap();
        ring.add(mallory.public()).unwrap();
        // mallory signs a message claiming to come from ground-ops
        let env = seal_and_sign(&draft(b"x"), &mallory.signing, None, 1_767_225_600_000).unwrap();
        assert_eq!(
            env.verify(&ring).map(|_| ()),
            Err(Error::SignerNotAuthorized)
        );
    }
}
