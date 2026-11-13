//! Suite 1, "IL1-CNSA2": the CNSA 2.0 algorithm set, all from AWS-LC.
//!
//! | Purpose            | Algorithm    | Standard       |
//! |--------------------|--------------|----------------|
//! | Signature          | ML-DSA-87    | FIPS 204       |
//! | Key establishment  | ML-KEM-1024  | FIPS 203       |
//! | Key derivation     | HKDF-SHA-384 | SP 800-56C r2 / RFC 5869 |
//! | Encryption         | AES-256-GCM  | FIPS 197, SP 800-38D |
//! | Hash / key IDs     | SHA-384      | FIPS 180-4     |
//!
//! Signatures use ML-DSA's pure mode with an empty context string, so any
//! FIPS 204 implementation can verify them (OpenSSL 3.5+, Apple CryptoKit,
//! the JDK); domain separation lives in the signed structure instead
//! (`docs/SPECIFICATION.md` §5). Secret material is zeroized on drop.

use std::fmt;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::KeyPair as _;
use aws_lc_rs::{aead, digest, hkdf, kem, rand, signature};
use zeroize::Zeroizing;

use crate::error::Error;

/// ML-DSA-87 public key length.
pub const MLDSA87_PUBLIC_KEY_LEN: usize = 2592;
/// ML-DSA-87 signature length.
pub const MLDSA87_SIGNATURE_LEN: usize = 4627;
/// ML-DSA key-generation seed length (ξ in FIPS 204).
pub const MLDSA_SEED_LEN: usize = 32;
/// ML-KEM-1024 encapsulation (public) key length.
pub const MLKEM1024_ENCAPSULATION_KEY_LEN: usize = 1568;
/// ML-KEM-1024 decapsulation (private) key length, expanded form.
pub const MLKEM1024_DECAPSULATION_KEY_LEN: usize = 3168;
/// ML-KEM-1024 ciphertext length.
pub const MLKEM1024_CIPHERTEXT_LEN: usize = 1568;
/// ML-KEM shared secret length.
pub const SHARED_SECRET_LEN: usize = 32;
/// Key identifier length (SHA-384 of the raw public key).
pub const KEY_ID_LEN: usize = 48;
/// AES-256 key length.
pub const AES256_KEY_LEN: usize = 32;
/// AES-GCM nonce length.
pub const GCM_NONCE_LEN: usize = 12;
/// AES-GCM tag length.
pub const GCM_TAG_LEN: usize = 16;

/// DER prefix of an ML-DSA-87 SubjectPublicKeyInfo: algorithm OID
/// 2.16.840.1.101.3.4.3.19 (NIST CSOR) with no parameters, then the 2592-byte key
/// as a BIT STRING, per the IETF LAMPS ML-DSA X.509 profile.
const MLDSA87_SPKI_PREFIX: [u8; 22] = [
    0x30, 0x82, 0x0a, 0x32, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
    0x13, 0x03, 0x82, 0x0a, 0x21, 0x00,
];

/// SHA-384 of `data`.
#[must_use]
pub fn sha384(data: &[u8]) -> [u8; 48] {
    let d = digest::digest(&digest::SHA384, data);
    let mut out = [0u8; 48];
    out.copy_from_slice(d.as_ref());
    out
}

/// A key identifier: SHA-384 of the raw public key bytes.
#[must_use]
pub fn key_id(public_key: &[u8]) -> [u8; KEY_ID_LEN] {
    sha384(public_key)
}

/// Fill `buf` from the system random generator (the DRBG inside AWS-LC).
///
/// # Errors
/// [`Error::Crypto`] if the generator fails.
pub fn random(buf: &mut [u8]) -> Result<(), Error> {
    rand::fill(buf).map_err(|_| Error::Crypto("system random generator failed"))
}

/// An ML-DSA-87 signing key.
pub struct SigningKey {
    pair: signature::PqdsaKeyPair,
}

impl SigningKey {
    /// A fresh key from the module's own generator (the FIPS-approved path).
    ///
    /// # Errors
    /// [`Error::Crypto`] if key generation fails.
    pub fn generate() -> Result<Self, Error> {
        signature::PqdsaKeyPair::generate(&signature::ML_DSA_87_SIGNING)
            .map(|pair| Self { pair })
            .map_err(|_| Error::Crypto("ML-DSA-87 key generation failed"))
    }

    /// The key FIPS 204 derives from a 32-byte seed. Deterministic: used for
    /// published test vectors. Real keys come from [`SigningKey::generate`].
    ///
    /// # Errors
    /// [`Error::Key`] if the seed is not 32 bytes.
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        signature::PqdsaKeyPair::from_seed(&signature::ML_DSA_87_SIGNING, seed)
            .map(|pair| Self { pair })
            .map_err(|_| Error::Key("ML-DSA-87 seed must be 32 bytes"))
    }

    /// Load a PKCS#8 (seed or expanded form) ML-DSA-87 private key.
    ///
    /// # Errors
    /// [`Error::Key`] if it is not an ML-DSA-87 PKCS#8 key.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, Error> {
        signature::PqdsaKeyPair::from_pkcs8(&signature::ML_DSA_87_SIGNING, der)
            .map(|pair| Self { pair })
            .map_err(|_| Error::Key("not an ML-DSA-87 PKCS#8 private key"))
    }

    /// The private key as PKCS#8 v1 DER in seed form (the IETF LAMPS profile's
    /// recommended private-key encoding).
    ///
    /// # Errors
    /// [`Error::Crypto`] if the seed is not available.
    pub fn to_pkcs8(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.pair
            .to_pkcs8v1()
            .map(|doc| Zeroizing::new(doc.as_ref().to_vec()))
            .map_err(|_| Error::Crypto("ML-DSA-87 key has no seed to serialize"))
    }

    /// The raw 2592-byte public key.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.pair.public_key().as_ref().to_vec()
    }

    /// The public key as X.509 SubjectPublicKeyInfo DER.
    ///
    /// # Errors
    /// [`Error::Crypto`] if serialization fails.
    pub fn public_key_spki(&self) -> Result<Vec<u8>, Error> {
        self.pair
            .public_key()
            .as_der()
            .map(|der| der.as_ref().to_vec())
            .map_err(|_| Error::Crypto("SubjectPublicKeyInfo serialization failed"))
    }

    /// This key's identifier.
    #[must_use]
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        key_id(self.pair.public_key().as_ref())
    }

    /// Sign `message` (ML-DSA pure mode, empty context, hedged randomness).
    ///
    /// # Errors
    /// [`Error::Crypto`] if signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut sig = vec![0u8; MLDSA87_SIGNATURE_LEN];
        let n = self
            .pair
            .sign(message, &mut sig)
            .map_err(|_| Error::Crypto("ML-DSA-87 signing failed"))?;
        sig.truncate(n);
        Ok(sig)
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("algorithm", &"ML-DSA-87")
            .field("key_id", &crate::hex::encode(&self.key_id()))
            .finish_non_exhaustive()
    }
}

/// Verify an ML-DSA-87 signature against a raw public key.
///
/// # Errors
/// [`Error::Key`] for a wrong-length key, [`Error::BadSignature`] otherwise.
pub fn verify(public_key: &[u8], message: &[u8], sig: &[u8]) -> Result<(), Error> {
    if public_key.len() != MLDSA87_PUBLIC_KEY_LEN {
        return Err(Error::Key("ML-DSA-87 public key must be 2592 bytes"));
    }
    if sig.len() != MLDSA87_SIGNATURE_LEN {
        return Err(Error::BadSignature);
    }
    signature::UnparsedPublicKey::new(&signature::ML_DSA_87, public_key)
        .verify(message, sig)
        .map_err(|_| Error::BadSignature)
}

/// Wrap a raw ML-DSA-87 public key as SubjectPublicKeyInfo DER, for tools
/// that import X.509 keys (OpenSSL, the JDK's `X509EncodedKeySpec`).
///
/// # Errors
/// [`Error::Key`] for a wrong-length key.
pub fn mldsa87_spki(public_key: &[u8]) -> Result<Vec<u8>, Error> {
    if public_key.len() != MLDSA87_PUBLIC_KEY_LEN {
        return Err(Error::Key("ML-DSA-87 public key must be 2592 bytes"));
    }
    Ok([&MLDSA87_SPKI_PREFIX[..], public_key].concat())
}

/// An ML-KEM-1024 decapsulation key with its encapsulation key.
pub struct DecapsulationKey {
    inner: kem::DecapsulationKey,
    encapsulation_key: Vec<u8>,
}

impl DecapsulationKey {
    /// A fresh key pair.
    ///
    /// # Errors
    /// [`Error::Crypto`] if key generation fails.
    pub fn generate() -> Result<Self, Error> {
        let inner = kem::DecapsulationKey::generate(&kem::ML_KEM_1024)
            .map_err(|_| Error::Crypto("ML-KEM-1024 key generation failed"))?;
        Self::wrap(inner)
    }

    /// Load the expanded 3168-byte decapsulation key.
    ///
    /// FIPS 203 lays it out as `dk_PKE ‖ ek ‖ H(ek) ‖ z`, so the
    /// encapsulation key is read from its fixed offset. The key must pass the
    /// FIPS 203 §7.3 hash check (`H(ek)` = SHA3-256 of the embedded `ek`) and
    /// a pairwise-consistency test (encapsulate to `ek`, decapsulate with the
    /// key, same secret) before it is accepted.
    ///
    /// # Errors
    /// [`Error::Key`] if it is not a consistent ML-KEM-1024 decapsulation key.
    pub fn from_bytes(dk: &[u8]) -> Result<Self, Error> {
        const EK: core::ops::Range<usize> = 1536..1536 + MLKEM1024_ENCAPSULATION_KEY_LEN;
        const HASH: core::ops::Range<usize> = EK.end..EK.end + 32;
        if dk.len() != MLKEM1024_DECAPSULATION_KEY_LEN {
            return Err(Error::Key(
                "ML-KEM-1024 decapsulation key must be 3168 bytes",
            ));
        }
        let inner = kem::DecapsulationKey::new(&kem::ML_KEM_1024, dk)
            .map_err(|_| Error::Key("not an ML-KEM-1024 decapsulation key"))?;
        let (Some(ek), Some(ek_hash)) = (dk.get(EK), dk.get(HASH)) else {
            return Err(Error::Key("ML-KEM-1024 decapsulation key is truncated"));
        };
        if digest::digest(&digest::SHA3_256, ek).as_ref() != ek_hash {
            return Err(Error::Key(
                "ML-KEM-1024 decapsulation key fails the FIPS 203 hash check",
            ));
        }
        let key = Self {
            inner,
            encapsulation_key: ek.to_vec(),
        };
        let (ct, secret) = encapsulate(ek)?;
        if *key.decapsulate(&ct)? != *secret {
            return Err(Error::Key(
                "ML-KEM-1024 decapsulation key does not match its encapsulation key",
            ));
        }
        Ok(key)
    }

    fn wrap(inner: kem::DecapsulationKey) -> Result<Self, Error> {
        let bytes = inner
            .encapsulation_key()
            .and_then(|ek| ek.key_bytes())
            .map_err(|_| Error::Crypto("ML-KEM-1024 encapsulation key export failed"))?;
        let raw: &[u8] = bytes.as_ref();
        let encapsulation_key = raw.to_vec();
        Ok(Self {
            inner,
            encapsulation_key,
        })
    }

    /// The expanded decapsulation key bytes (secret).
    ///
    /// # Errors
    /// [`Error::Crypto`] if export fails.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.inner
            .key_bytes()
            .map(|bytes| {
                let raw: &[u8] = bytes.as_ref();
                Zeroizing::new(raw.to_vec())
            })
            .map_err(|_| Error::Crypto("ML-KEM-1024 decapsulation key export failed"))
    }

    /// The 1568-byte encapsulation key.
    #[must_use]
    pub fn encapsulation_key(&self) -> &[u8] {
        &self.encapsulation_key
    }

    /// The encapsulation key's identifier.
    #[must_use]
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        key_id(&self.encapsulation_key)
    }

    /// Recover the shared secret from a ciphertext.
    ///
    /// # Errors
    /// [`Error::Decrypt`] for a wrong-length ciphertext or a module failure.
    pub fn decapsulate(
        &self,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<[u8; SHARED_SECRET_LEN]>, Error> {
        if ciphertext.len() != MLKEM1024_CIPHERTEXT_LEN {
            return Err(Error::Decrypt);
        }
        let ss = self
            .inner
            .decapsulate(kem::Ciphertext::from(ciphertext))
            .map_err(|_| Error::Decrypt)?;
        let mut out = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
        if ss.as_ref().len() != SHARED_SECRET_LEN {
            return Err(Error::Decrypt);
        }
        out.copy_from_slice(ss.as_ref());
        Ok(out)
    }
}

impl fmt::Debug for DecapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecapsulationKey")
            .field("algorithm", &"ML-KEM-1024")
            .field("key_id", &crate::hex::encode(&self.key_id()))
            .finish_non_exhaustive()
    }
}

/// Encapsulate to a recipient's ML-KEM-1024 key: (ciphertext, shared secret).
///
/// # Errors
/// [`Error::Key`] for an invalid key, [`Error::Crypto`] if encapsulation fails.
pub fn encapsulate(
    encapsulation_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_SECRET_LEN]>), Error> {
    if encapsulation_key.len() != MLKEM1024_ENCAPSULATION_KEY_LEN {
        return Err(Error::Key(
            "ML-KEM-1024 encapsulation key must be 1568 bytes",
        ));
    }
    let key = kem::EncapsulationKey::new(&kem::ML_KEM_1024, encapsulation_key)
        .map_err(|_| Error::Key("not an ML-KEM-1024 encapsulation key"))?;
    let (ct, ss) = key
        .encapsulate()
        .map_err(|_| Error::Crypto("ML-KEM-1024 encapsulation failed"))?;
    if ss.as_ref().len() != SHARED_SECRET_LEN {
        return Err(Error::Crypto(
            "ML-KEM-1024 shared secret has the wrong length",
        ));
    }
    let mut secret = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
    secret.copy_from_slice(ss.as_ref());
    Ok((ct.as_ref().to_vec(), secret))
}

struct OkmLen(usize);

impl hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-SHA-384 (extract-then-expand) into `out`.
///
/// # Errors
/// [`Error::Crypto`] if `out` is longer than HKDF allows (255 × 48 bytes).
pub fn hkdf_sha384(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA384, salt).extract(ikm);
    let info_parts = [info];
    prk.expand(&info_parts, OkmLen(out.len()))
        .and_then(|okm| okm.fill(out))
        .map_err(|_| Error::Crypto("HKDF-SHA-384 expansion failed"))
}

fn gcm_key(key: &[u8; AES256_KEY_LEN]) -> Result<aead::LessSafeKey, Error> {
    aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map(aead::LessSafeKey::new)
        .map_err(|_| Error::Crypto("AES-256-GCM key setup failed"))
}

/// AES-256-GCM encrypt; returns ciphertext ‖ 16-byte tag.
///
/// # Errors
/// [`Error::Crypto`] if the module refuses (e.g. plaintext too long).
pub fn aes256gcm_seal(
    key: &[u8; AES256_KEY_LEN],
    nonce: &[u8; GCM_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut in_out = plaintext.to_vec();
    gcm_key(key)?
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(*nonce),
            aead::Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| Error::Crypto("AES-256-GCM encryption failed"))?;
    Ok(in_out)
}

/// AES-256-GCM decrypt and authenticate ciphertext ‖ tag.
///
/// # Errors
/// [`Error::Decrypt`] if authentication fails.
pub fn aes256gcm_open(
    key: &[u8; AES256_KEY_LEN],
    nonce: &[u8; GCM_NONCE_LEN],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut in_out = sealed.to_vec();
    let len = gcm_key(key)?
        .open_in_place(
            aead::Nonce::assume_unique_for_key(*nonce),
            aead::Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| Error::Decrypt)?
        .len();
    in_out.truncate(len);
    Ok(in_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa87_sign_verify_and_spki() {
        let key = SigningKey::from_seed(&[7u8; 32]).unwrap();
        let again = SigningKey::from_seed(&[7u8; 32]).unwrap();
        assert_eq!(
            key.public_key(),
            again.public_key(),
            "seed keygen is deterministic"
        );
        let pk = key.public_key();
        assert_eq!(pk.len(), MLDSA87_PUBLIC_KEY_LEN);
        let sig = key.sign(b"interlingua").unwrap();
        assert_eq!(sig.len(), MLDSA87_SIGNATURE_LEN);
        verify(&pk, b"interlingua", &sig).unwrap();
        assert_eq!(verify(&pk, b"interlinguA", &sig), Err(Error::BadSignature));
        // Our hand-built SPKI matches AWS-LC's own encoder byte for byte.
        assert_eq!(mldsa87_spki(&pk).unwrap(), key.public_key_spki().unwrap());
        // PKCS#8 round trip keeps the same key.
        let reloaded = SigningKey::from_pkcs8(&key.to_pkcs8().unwrap()).unwrap();
        assert_eq!(reloaded.public_key(), pk);
    }

    #[test]
    fn mlkem1024_round_trip() {
        let dk = DecapsulationKey::generate().unwrap();
        assert_eq!(
            dk.encapsulation_key().len(),
            MLKEM1024_ENCAPSULATION_KEY_LEN
        );
        let (ct, ss) = encapsulate(dk.encapsulation_key()).unwrap();
        assert_eq!(ct.len(), MLKEM1024_CIPHERTEXT_LEN);
        assert_eq!(*dk.decapsulate(&ct).unwrap(), *ss);
        let reloaded = DecapsulationKey::from_bytes(&dk.to_bytes().unwrap()).unwrap();
        assert_eq!(reloaded.encapsulation_key(), dk.encapsulation_key());
        assert_eq!(*reloaded.decapsulate(&ct).unwrap(), *ss);
    }

    #[test]
    fn hkdf_and_gcm() {
        // RFC 5869 has no SHA-384 vectors; this pins our output for the
        // cross-language vectors and checks the AEAD round trip.
        let mut okm = [0u8; 44];
        hkdf_sha384(&[0x0b; 22], &[0x00; 13], b"info", &mut okm).unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&okm[..32]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&okm[32..]);
        let sealed = aes256gcm_seal(&key, &nonce, b"aad", b"payload").unwrap();
        assert_eq!(sealed.len(), 7 + GCM_TAG_LEN);
        assert_eq!(
            aes256gcm_open(&key, &nonce, b"aad", &sealed).unwrap(),
            b"payload"
        );
        assert_eq!(
            aes256gcm_open(&key, &nonce, b"AAD", &sealed),
            Err(Error::Decrypt)
        );
    }
}
