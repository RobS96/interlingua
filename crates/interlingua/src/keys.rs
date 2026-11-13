//! Key bundles and keyrings.
//!
//! A domain owns two key pairs: ML-DSA-87 to sign what it sends and
//! ML-KEM-1024 to receive sealed payloads. Bundles are plain text, one
//! `name value` pair per line with values in hex, so any language (or `awk`)
//! can read them:
//!
//! ```text
//! interlingua-secret-key v1
//! domain ground-ops
//! suite IL1-CNSA2
//! mldsa87-pkcs8 3034…
//! mlkem1024-dk 2a91…
//! ```
//!
//! A public bundle has `interlingua-public-key v1`, `mldsa87-pk` and
//! `mlkem1024-ek` instead. A keyring is public bundles one after another; it
//! is a trust store, and the binding of each key to one domain is what the
//! router enforces (a key signs only for its own domain).

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::crypto::{self, DecapsulationKey, KEY_ID_LEN, SigningKey};
use crate::error::Error;
use crate::{hex, ident};

const SECRET_MAGIC: &str = "interlingua-secret-key v1";
const PUBLIC_MAGIC: &str = "interlingua-public-key v1";
const SUITE_NAME: &str = "IL1-CNSA2";

/// A domain's private keys.
#[derive(Debug)]
pub struct SecretKeys {
    /// The domain these keys belong to.
    pub domain: String,
    /// ML-DSA-87 signing key.
    pub signing: SigningKey,
    /// ML-KEM-1024 decapsulation key.
    pub decapsulation: DecapsulationKey,
}

/// A domain's public keys, as distributed in keyrings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeys {
    /// The domain these keys belong to.
    pub domain: String,
    /// Raw ML-DSA-87 public key.
    pub verifying_key: Vec<u8>,
    /// Raw ML-KEM-1024 encapsulation key.
    pub encapsulation_key: Vec<u8>,
}

impl PublicKeys {
    /// Identifier of the signing key.
    #[must_use]
    pub fn signing_key_id(&self) -> [u8; KEY_ID_LEN] {
        crypto::key_id(&self.verifying_key)
    }

    /// Identifier of the encapsulation key.
    #[must_use]
    pub fn encapsulation_key_id(&self) -> [u8; KEY_ID_LEN] {
        crypto::key_id(&self.encapsulation_key)
    }

    /// The bundle text.
    #[must_use]
    pub fn to_text(&self) -> String {
        format!(
            "{PUBLIC_MAGIC}\ndomain {}\nsuite {SUITE_NAME}\nmldsa87-pk {}\nmlkem1024-ek {}\n",
            self.domain,
            hex::encode(&self.verifying_key),
            hex::encode(&self.encapsulation_key),
        )
    }

    /// Parse one public bundle.
    ///
    /// # Errors
    /// [`Error::Key`] or [`Error::Identifier`].
    pub fn parse(text: &str) -> Result<Self, Error> {
        let fields = parse_bundle(
            text,
            PUBLIC_MAGIC,
            &["domain", "suite", "mldsa87-pk", "mlkem1024-ek"],
        )?;
        let domain = field(&fields, "domain")?.to_owned();
        ident::domain(&domain)?;
        let verifying_key = hex::decode(field(&fields, "mldsa87-pk")?)
            .map_err(|_| Error::Key("mldsa87-pk is not hex"))?;
        let encapsulation_key = hex::decode(field(&fields, "mlkem1024-ek")?)
            .map_err(|_| Error::Key("mlkem1024-ek is not hex"))?;
        if verifying_key.len() != crypto::MLDSA87_PUBLIC_KEY_LEN {
            return Err(Error::Key("mldsa87-pk must be 2592 bytes"));
        }
        if encapsulation_key.len() != crypto::MLKEM1024_ENCAPSULATION_KEY_LEN {
            return Err(Error::Key("mlkem1024-ek must be 1568 bytes"));
        }
        // Reject keys the module cannot load now, not at first use.
        crypto::encapsulate(&encapsulation_key)?;
        Ok(Self {
            domain,
            verifying_key,
            encapsulation_key,
        })
    }
}

impl SecretKeys {
    /// Fresh keys for `domain`.
    ///
    /// # Errors
    /// [`Error::Identifier`] for a bad name, [`Error::Crypto`] if generation fails.
    pub fn generate(domain: &str) -> Result<Self, Error> {
        ident::domain(domain)?;
        Ok(Self {
            domain: domain.to_owned(),
            signing: SigningKey::generate()?,
            decapsulation: DecapsulationKey::generate()?,
        })
    }

    /// The matching public bundle.
    #[must_use]
    pub fn public(&self) -> PublicKeys {
        PublicKeys {
            domain: self.domain.clone(),
            verifying_key: self.signing.public_key(),
            encapsulation_key: self.decapsulation.encapsulation_key().to_vec(),
        }
    }

    /// The secret bundle text (handle as a secret: it holds both private keys).
    ///
    /// # Errors
    /// [`Error::Crypto`] if a key cannot be exported.
    pub fn to_text(&self) -> Result<Zeroizing<String>, Error> {
        let pkcs8 = self.signing.to_pkcs8()?;
        let dk = self.decapsulation.to_bytes()?;
        Ok(Zeroizing::new(format!(
            "{SECRET_MAGIC}\ndomain {}\nsuite {SUITE_NAME}\nmldsa87-pkcs8 {}\nmlkem1024-dk {}\n",
            self.domain,
            hex::encode(&pkcs8),
            hex::encode(&dk),
        )))
    }

    /// Parse a secret bundle.
    ///
    /// # Errors
    /// [`Error::Key`] or [`Error::Identifier`].
    pub fn parse(text: &str) -> Result<Self, Error> {
        let fields = parse_bundle(
            text,
            SECRET_MAGIC,
            &["domain", "suite", "mldsa87-pkcs8", "mlkem1024-dk"],
        )?;
        let domain = field(&fields, "domain")?.to_owned();
        ident::domain(&domain)?;
        let pkcs8 = Zeroizing::new(
            hex::decode(field(&fields, "mldsa87-pkcs8")?)
                .map_err(|_| Error::Key("mldsa87-pkcs8 is not hex"))?,
        );
        let dk = Zeroizing::new(
            hex::decode(field(&fields, "mlkem1024-dk")?)
                .map_err(|_| Error::Key("mlkem1024-dk is not hex"))?,
        );
        Ok(Self {
            domain,
            signing: SigningKey::from_pkcs8(&pkcs8)?,
            decapsulation: DecapsulationKey::from_bytes(&dk)?,
        })
    }
}

fn field<'a>(fields: &'a BTreeMap<&str, &'a str>, name: &str) -> Result<&'a str, Error> {
    fields
        .get(name)
        .copied()
        .ok_or(Error::Key("key bundle is missing a field"))
}

fn parse_bundle<'a>(
    text: &'a str,
    magic: &str,
    names: &[&'static str],
) -> Result<BTreeMap<&'static str, &'a str>, Error> {
    let mut lines = text
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty() && !l.starts_with('#'));
    if lines.next() != Some(magic) {
        return Err(Error::Key("key bundle has the wrong header line"));
    }
    let mut fields = BTreeMap::new();
    for line in lines {
        let (name, value) = line
            .split_once(' ')
            .ok_or(Error::Key("key bundle lines are `name value`"))?;
        let name = names
            .iter()
            .copied()
            .find(|n| *n == name)
            .ok_or(Error::Key("key bundle has an unknown field"))?;
        if fields.insert(name, value.trim()).is_some() {
            return Err(Error::Key("key bundle repeats a field"));
        }
    }
    if fields.len() != names.len() {
        return Err(Error::Key("key bundle is missing a field"));
    }
    if fields.get("suite") != Some(&SUITE_NAME) {
        return Err(Error::Key("key bundle suite must be IL1-CNSA2"));
    }
    Ok(fields)
}

/// Public keys the router trusts, indexed by key identifier.
#[derive(Debug, Clone, Default)]
pub struct Keyring {
    entries: Vec<PublicKeys>,
    by_signing_id: BTreeMap<[u8; KEY_ID_LEN], usize>,
    by_kem_id: BTreeMap<[u8; KEY_ID_LEN], usize>,
}

impl Keyring {
    /// An empty keyring.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a domain's public keys. A key may appear once only, so it can never
    /// be bound to two domains.
    ///
    /// # Errors
    /// [`Error::Key`] if either key is already present.
    pub fn add(&mut self, keys: PublicKeys) -> Result<(), Error> {
        let sid = keys.signing_key_id();
        let kid = keys.encapsulation_key_id();
        if self.by_signing_id.contains_key(&sid) || self.by_kem_id.contains_key(&kid) {
            return Err(Error::Key("a key appears twice in the keyring"));
        }
        let index = self.entries.len();
        self.entries.push(keys);
        self.by_signing_id.insert(sid, index);
        self.by_kem_id.insert(kid, index);
        Ok(())
    }

    /// Parse concatenated public bundles.
    ///
    /// # Errors
    /// [`Error::Key`] or [`Error::Identifier`].
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut ring = Self::new();
        let mut current = String::new();
        let flush = |chunk: &str, ring: &mut Self| -> Result<(), Error> {
            // Text before the first bundle (comments, blank lines) is not a bundle.
            if chunk.lines().any(|l| l.trim_end() == PUBLIC_MAGIC) {
                ring.add(PublicKeys::parse(chunk)?)?;
            } else if chunk
                .lines()
                .any(|l| !l.trim().is_empty() && !l.starts_with('#'))
            {
                return Err(Error::Key("keyring text outside a public key bundle"));
            }
            Ok(())
        };
        for line in text.lines() {
            if line.trim_end() == PUBLIC_MAGIC {
                flush(&current, &mut ring)?;
                current.clear();
            }
            current.push_str(line);
            current.push('\n');
        }
        flush(&current, &mut ring)?;
        Ok(ring)
    }

    /// Who owns the signing key with this identifier.
    #[must_use]
    pub fn signer(&self, key_id: &[u8; KEY_ID_LEN]) -> Option<&PublicKeys> {
        self.by_signing_id
            .get(key_id)
            .and_then(|i| self.entries.get(*i))
    }

    /// Who owns the encapsulation key with this identifier.
    #[must_use]
    pub fn recipient(&self, key_id: &[u8; KEY_ID_LEN]) -> Option<&PublicKeys> {
        self.by_kem_id
            .get(key_id)
            .and_then(|i| self.entries.get(*i))
    }

    /// The first (primary) bundle for a domain.
    #[must_use]
    pub fn primary(&self, domain: &str) -> Option<&PublicKeys> {
        self.entries.iter().find(|k| k.domain == domain)
    }

    /// Every bundle, in insertion order.
    #[must_use]
    pub fn entries(&self) -> &[PublicKeys] {
        &self.entries
    }

    /// The keyring as concatenated bundle text.
    #[must_use]
    pub fn to_text(&self) -> String {
        self.entries
            .iter()
            .map(PublicKeys::to_text)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundles_round_trip() {
        let secret = SecretKeys::generate("ground-ops").unwrap();
        let text = secret.to_text().unwrap();
        let again = SecretKeys::parse(&text).unwrap();
        assert_eq!(again.public(), secret.public());
        let public = PublicKeys::parse(&secret.public().to_text()).unwrap();
        assert_eq!(public, secret.public());
        assert!(SecretKeys::parse(&text.replace("ground-ops", "Ground")).is_err());
        assert!(
            PublicKeys::parse(&text).is_err(),
            "a secret bundle is not a public bundle"
        );
    }

    #[test]
    fn keyring_binds_each_key_once() {
        let a = SecretKeys::generate("alpha").unwrap().public();
        let b = SecretKeys::generate("bravo").unwrap().public();
        let ring = Keyring::parse(&format!("{}\n{}", a.to_text(), b.to_text())).unwrap();
        assert_eq!(
            ring.signer(&a.signing_key_id()).map(|k| k.domain.as_str()),
            Some("alpha")
        );
        assert_eq!(
            ring.recipient(&b.encapsulation_key_id())
                .map(|k| k.domain.as_str()),
            Some("bravo")
        );
        let mut dup = ring.clone();
        let mut stolen = a.clone();
        stolen.domain = "bravo".into();
        assert!(
            dup.add(stolen).is_err(),
            "a key cannot be re-bound to another domain"
        );
    }
}
