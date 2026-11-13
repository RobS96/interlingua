//! `il vectors generate <dir>`: regenerate `envelope.rsp` and `routing.rsp`.
//!
//! Expected results are written from the scenario tables below, not computed
//! by running the router or the decoder: the vectors state the design, and
//! `il vectors check` (and every binding) proves an implementation meets it.
//! Signatures and KEM ciphertexts are randomized, so each run produces new
//! bytes with the same meaning. Test keys are reused from
//! `test-secrets.txt` when it exists.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use interlingua::cbor::{self, Value};
use interlingua::crypto::{DecapsulationKey, SigningKey};
use interlingua::envelope::{self, Draft, SealTrace};
use interlingua::{Envelope, Error, Keyring, Label, SecretKeys, hex, vectors};

use crate::{Exit, Failure, Outcome};

/// 2026-01-01T00:00:00Z.
const T0: u64 = 1_767_225_600_000;
const HOUR: u64 = 3_600_000;
const DOMAINS: [&str; 6] = [
    "ground-ops",
    "relay-alpha",
    "space-segment",
    "science-lab",
    "archive",
    "quarantine",
];

const SECRETS_HEADER: &str = "\
# interlingua conformance TEST KEYS. Published on purpose so every
# implementation can open the sealed vectors: NEVER use them for real traffic.
# ML-DSA-87 keys are FIPS 204 keys from the fixed seeds 0x01…01 to 0x06…06
# (one per domain, in keyring order); ML-KEM-1024 keys are random, fixed here.
";

const KEYRING_HEADER: &str = "\
# interlingua conformance keyring: public halves of test-secrets.txt.
# The binding of each key to one domain is what routers enforce.
";

struct Rsp(String);

impl Rsp {
    fn new(header: &str) -> Self {
        Self(header.to_owned())
    }

    fn section(&mut self, name: &str) {
        let _ = write!(self.0, "\n[{name}]\n");
    }

    fn record(&mut self, fields: &[(&str, String)]) {
        self.0.push('\n');
        for (k, v) in fields {
            let _ = writeln!(self.0, "{k} = {v}");
        }
    }
}

struct Lab {
    keys: BTreeMap<String, SecretKeys>,
}

impl Lab {
    fn key(&self, domain: &str) -> Result<&SecretKeys, Failure> {
        self.keys
            .get(domain)
            .ok_or_else(|| Failure::new(Exit::DataErr, format!("no test key for {domain}")))
    }

    #[allow(clippy::too_many_arguments)]
    fn make(
        &self,
        signer: &SigningKey,
        src: &str,
        dst: &str,
        label: &str,
        seal_to: Option<&str>,
        payload: &[u8],
        ttl_ms: u64,
        max_hops: u8,
    ) -> Result<(Envelope, Option<SealTrace>), Failure> {
        let ek = match seal_to {
            Some(d) => Some(self.key(d)?.decapsulation.encapsulation_key().to_vec()),
            None => None,
        };
        let draft = Draft {
            src,
            dst,
            label: Label::parse(label)?,
            content_type: if payload.is_ascii() {
                "application/octet-stream"
            } else {
                "text/plain"
            },
            ttl_ms,
            max_hops,
            payload,
        };
        Ok(envelope::seal_and_sign_traced(
            &draft,
            signer,
            ek.as_deref(),
            T0,
        )?)
    }

    fn send(
        &self,
        src: &str,
        dst: &str,
        label: &str,
        seal_to: Option<&str>,
        payload: &[u8],
    ) -> Result<Envelope, Failure> {
        Ok(self
            .make(
                &self.key(src)?.signing,
                src,
                dst,
                label,
                seal_to,
                payload,
                HOUR,
                8,
            )?
            .0)
    }
}

fn wire(env: &Envelope) -> Result<String, Failure> {
    Ok(hex::encode(&env.encode()?))
}

/// An envelope assembled from raw parts, for non-canonical and schema vectors.
fn raw_envelope(
    protected: &[u8],
    unprotected: &[u8],
    payload: &[u8],
    sig: &[u8],
) -> Result<String, Error> {
    let mut out = vec![0x84];
    out.extend(cbor::encode(&Value::Bytes(protected.to_vec()))?);
    out.extend_from_slice(unprotected);
    out.extend(cbor::encode(&Value::Bytes(payload.to_vec()))?);
    out.extend(cbor::encode(&Value::Bytes(sig.to_vec()))?);
    Ok(hex::encode(&out))
}

fn load_or_create_keys(dir: &Path) -> Result<Lab, Failure> {
    let path = dir.join("test-secrets.txt");
    if path.exists() {
        let text = fs::read_to_string(&path)
            .map_err(|e| Failure::new(Exit::NoInput, format!("{}: {e}", path.display())))?;
        return Ok(Lab {
            keys: vectors::parse_secret_bundles(&text)?,
        });
    }
    let mut keys = BTreeMap::new();
    let mut text = SECRETS_HEADER.to_owned();
    for (seed, domain) in (1u8..).zip(DOMAINS) {
        let k = SecretKeys {
            domain: domain.to_owned(),
            signing: SigningKey::from_seed(&[seed; 32])?,
            decapsulation: DecapsulationKey::generate()?,
        };
        text.push('\n');
        text.push_str(&k.to_text()?);
        keys.insert(domain.to_owned(), k);
    }
    fs::write(&path, text)
        .map_err(|e| Failure::new(Exit::CantCreate, format!("{}: {e}", path.display())))?;
    Ok(Lab { keys })
}

pub(crate) fn run(dir: &Path) -> Outcome {
    let lab = load_or_create_keys(dir)?;
    let mut ring = Keyring::new();
    for d in DOMAINS {
        ring.add(lab.key(d)?.public())?;
    }
    write(
        dir,
        "keyring.pub",
        &format!("{KEYRING_HEADER}\n{}", ring.to_text()),
    )?;
    write(dir, "envelope.rsp", &envelope_vectors(&lab)?)?;
    write(dir, "routing.rsp", &routing_vectors(&lab)?)?;
    let note = format!(
        "wrote keyring.pub, envelope.rsp and routing.rsp in {}\n",
        dir.display()
    );
    let _ = std::io::Write::write_all(&mut std::io::stderr(), note.as_bytes());
    Ok(())
}

fn write(dir: &Path, name: &str, text: &str) -> Outcome {
    fs::write(dir.join(name), text)
        .map_err(|e| Failure::new(Exit::CantCreate, format!("{name}: {e}")))
}

fn valid_fields(
    name: &str,
    env: &Envelope,
    payload: &[u8],
    recipient: Option<&str>,
    trace: Option<&SealTrace>,
) -> Result<Vec<(&'static str, String)>, Failure> {
    let mut f = vec![
        ("name", name.to_owned()),
        ("signer", env.header.src.clone()),
        ("envelope", wire(env)?),
        ("expect", "valid".to_owned()),
        ("payload", hex::encode(payload)),
    ];
    if let Some(r) = recipient {
        f.push(("recipient", r.to_owned()));
    }
    f.push(("signed", hex::encode(&env.signed_bytes()?)));
    f.push(("signature", hex::encode(&env.signature)));
    if let Some(t) = trace {
        let parts = cbor::decode(&env.payload).map_err(Error::from)?;
        let (Some(kem_ct), Some(aead_ct)) = (
            parts
                .as_array()
                .and_then(|a| a.get(1))
                .and_then(Value::as_bytes),
            parts
                .as_array()
                .and_then(|a| a.get(2))
                .and_then(Value::as_bytes),
        ) else {
            return Err(Failure::new(
                Exit::Software,
                "sealed payload has an unexpected shape",
            ));
        };
        f.push(("kem-ct", hex::encode(kem_ct)));
        f.push(("kem-ss", hex::encode(&t.shared_secret)));
        f.push(("aead-key", hex::encode(&t.key)));
        f.push(("aead-nonce", hex::encode(&t.nonce)));
        f.push(("aead-aad", hex::encode(&t.aad)));
        f.push(("aead-ct", hex::encode(aead_ct)));
    }
    Ok(f)
}

fn envelope_vectors(lab: &Lab) -> Result<String, Failure> {
    let mut rsp = Rsp::new(
        "\
# interlingua conformance vectors: envelopes (wire format 1, suite IL1-CNSA2)
# Regenerate with `il vectors generate spec/vectors`. Keys: keyring.pub and
# test-secrets.txt (published TEST keys).
#
# name       what the record shows
# envelope   the envelope (hex)
# expect     valid, or error:<id> (docs/SPECIFICATION.md section 9 lists the ids)
# payload    the payload after verify + open (valid records)
# recipient  domain whose test key opens a sealed payload
# signer     source domain (its ML-DSA-87 key is in keyring.pub)
# signed     bytes the signature covers: CBOR [\"IL1-Sign\", protected, payload]
# signature  the ML-DSA-87 signature (pure mode, empty context)
# kem-ct, kem-ss, aead-key, aead-nonce, aead-aad, aead-ct
#            sealing intermediates, so independent ML-KEM, HKDF and AES-GCM
#            implementations can be checked against them
",
    );
    let label_low = "conf=low integ=moderate avail=moderate comp=science";
    let label_tc = "conf=moderate integ=high avail=high comp=tt-c";

    rsp.section("valid");
    let hello = b"hello, world";
    let env = lab.send("ground-ops", "science-lab", label_low, None, hello)?;
    rsp.record(&valid_fields("plaintext", &env, hello, None, None)?);

    let utf8 = "Ελληνικά · 日本語 · ℵ₀ · 🚀".as_bytes();
    let env = lab.send("ground-ops", "science-lab", label_low, None, utf8)?;
    rsp.record(&valid_fields("plaintext-utf8", &env, utf8, None, None)?);

    let command = b"ARM PAYLOAD BAY";
    let (sealed, trace) = lab.make(
        &lab.key("ground-ops")?.signing,
        "ground-ops",
        "space-segment",
        label_tc,
        Some("space-segment"),
        command,
        HOUR,
        8,
    )?;
    rsp.record(&valid_fields(
        "sealed",
        &sealed,
        command,
        Some("space-segment"),
        trace.as_ref(),
    )?);

    let empty = lab.send(
        "archive",
        "ground-ops",
        "conf=n/a integ=low avail=low",
        None,
        b"",
    )?;
    rsp.record(&valid_fields(
        "empty-public-payload",
        &empty,
        b"",
        None,
        None,
    )?);

    rsp.section("refused");
    let ground = lab.key("ground-ops")?;
    let mut tampered = env.clone();
    tampered.payload = b"hello, World".to_vec();
    rsp.record(&[
        ("name", "tampered-payload".into()),
        ("envelope", wire(&tampered)?),
        ("expect", "error:BadSignature".into()),
    ]);

    let mut wrong_sig = env.clone();
    if let Some(byte) = wrong_sig.signature.get_mut(100) {
        *byte ^= 0x01;
    }
    rsp.record(&[
        ("name", "tampered-signature".into()),
        ("envelope", wire(&wrong_sig)?),
        ("expect", "error:BadSignature".into()),
    ]);

    let rogue = SigningKey::from_seed(&[0xee; 32])?;
    let (unknown, _) = lab.make(
        &rogue,
        "ground-ops",
        "science-lab",
        label_low,
        None,
        hello,
        HOUR,
        8,
    )?;
    rsp.record(&[
        ("name", "unknown-signer".into()),
        ("envelope", wire(&unknown)?),
        ("expect", "error:UnknownSigner".into()),
    ]);

    let (spoof, _) = lab.make(
        &lab.key("science-lab")?.signing,
        "ground-ops",
        "science-lab",
        label_low,
        None,
        hello,
        HOUR,
        8,
    )?;
    rsp.record(&[
        ("name", "signer-not-authorized".into()),
        ("envelope", wire(&spoof)?),
        ("expect", "error:SignerNotAuthorized".into()),
    ]);

    rsp.record(&[
        ("name", "wrong-recipient".into()),
        ("envelope", wire(&sealed)?),
        ("recipient", "ground-ops".into()),
        ("expect", "error:WrongRecipient".into()),
    ]);
    rsp.record(&[
        ("name", "key-required".into()),
        ("envelope", wire(&sealed)?),
        ("expect", "error:KeyRequired".into()),
    ]);

    // A validly signed envelope whose sealed payload does not authenticate.
    let mut broken = sealed.clone();
    if let Some(last) = broken.payload.last_mut() {
        *last ^= 0x01;
    }
    broken.signature = ground.signing.sign(&broken.signed_bytes()?)?;
    rsp.record(&[
        ("name", "aead-tag-mismatch".into()),
        ("envelope", wire(&broken)?),
        ("recipient", "space-segment".into()),
        ("expect", "error:Decrypt".into()),
    ]);

    rsp.section("malformed");
    rsp.record(&[
        ("name", "non-canonical-hop-count".into()),
        (
            "envelope",
            raw_envelope(
                &env.protected,
                &[0xa1, 0x01, 0x18, 0x08],
                &env.payload,
                &env.signature,
            )?,
        ),
        ("expect", "error:Cbor/NonCanonicalInteger".into()),
    ]);
    let extra = cbor::encode(&Value::Map(vec![
        (Value::Unsigned(1), Value::Unsigned(8)),
        (Value::Unsigned(2), Value::Unsigned(0)),
    ]))
    .map_err(Error::from)?;
    rsp.record(&[
        ("name", "unknown-unprotected-field".into()),
        (
            "envelope",
            raw_envelope(&env.protected, &extra, &env.payload, &env.signature)?,
        ),
        ("expect", "error:Schema".into()),
    ]);
    let mut v2 = env.header.to_cbor();
    if let Value::Map(entries) = &mut v2
        && let Some((_, version)) = entries.first_mut()
    {
        *version = Value::Unsigned(2);
    }
    let v2 = cbor::encode(&v2).map_err(Error::from)?;
    rsp.record(&[
        ("name", "future-version".into()),
        (
            "envelope",
            raw_envelope(&v2, &[0xa1, 0x01, 0x08], &env.payload, &env.signature)?,
        ),
        ("expect", "error:Version".into()),
    ]);
    rsp.record(&[
        ("name", "not-an-envelope".into()),
        ("envelope", "a0".into()),
        ("expect", "error:Schema".into()),
    ]);
    rsp.record(&[
        ("name", "trailing-bytes".into()),
        ("envelope", format!("{}00", wire(&env)?)),
        ("expect", "error:Cbor/TrailingBytes".into()),
    ]);
    Ok(rsp.0)
}

fn routing_vectors(lab: &Lab) -> Result<String, Failure> {
    let mut rsp = Rsp::new(
        "\
# interlingua conformance vectors: routing decisions
# Policy: routing-policy.ndb · keys: keyring.pub · every envelope created at
# 2026-01-01T00:00:00Z (1767225600000), lifetime one hour, 8 hops unless noted.
# Regenerate with `il vectors generate spec/vectors`.
#
# Each [section] starts with fresh routers, one per node named in it.
# node      domain whose router decides
# from      domain it arrived from, or - when a local sender handed it over
# now       router time, Unix milliseconds
# envelope  hex, or `forwarded` for the previous record's forwarded output
# expect    deliver | forward:<next hop> | reject:<reason> (SPECIFICATION section 7)
",
    );
    let now = (T0 + 1_000).to_string();
    let rec = |rsp: &mut Rsp,
               name: &str,
               node: &str,
               from: &str,
               now: &str,
               envelope: String,
               expect: &str| {
        rsp.record(&[
            ("name", name.to_owned()),
            ("node", node.to_owned()),
            ("from", from.to_owned()),
            ("now", now.to_owned()),
            ("envelope", envelope),
            ("expect", expect.to_owned()),
        ]);
    };
    let tc = "conf=moderate integ=high avail=high comp=tt-c";
    let sci = "conf=low integ=moderate avail=low comp=science";
    let ops_low = "conf=low integ=moderate avail=low";

    rsp.section("uplink-sealed-multi-hop");
    let up = lab.send(
        "ground-ops",
        "space-segment",
        tc,
        Some("space-segment"),
        b"SAFE MODE EXIT",
    )?;
    rec(
        &mut rsp,
        "originate",
        "ground-ops",
        "-",
        &now,
        wire(&up)?,
        "forward:relay-alpha",
    );
    rec(
        &mut rsp,
        "relay",
        "relay-alpha",
        "ground-ops",
        &now,
        "forwarded".into(),
        "forward:space-segment",
    );
    rec(
        &mut rsp,
        "arrive",
        "space-segment",
        "relay-alpha",
        &now,
        "forwarded".into(),
        "deliver",
    );

    rsp.section("science-downlink");
    let down = lab.send("science-lab", "archive", sci, None, b"spectrum frame 0001")?;
    rec(
        &mut rsp,
        "originate",
        "science-lab",
        "-",
        &now,
        wire(&down)?,
        "forward:archive",
    );
    rec(
        &mut rsp,
        "arrive",
        "archive",
        "science-lab",
        &now,
        "forwarded".into(),
        "deliver",
    );

    rsp.section("size-limited-edge");
    let big = vec![0x5a_u8; 9_000];
    let large = lab.send("ground-ops", "archive", ops_low, None, &big)?;
    rec(
        &mut rsp,
        "route-around-8k-edge",
        "ground-ops",
        "-",
        &now,
        wire(&large)?,
        "forward:relay-alpha",
    );
    let small = lab.send("ground-ops", "archive", ops_low, None, b"index update")?;
    rec(
        &mut rsp,
        "direct-edge",
        "ground-ops",
        "-",
        &now,
        wire(&small)?,
        "forward:archive",
    );
    let ground = &lab.key("ground-ops")?.signing;
    let (tight, _) = lab.make(
        ground,
        "ground-ops",
        "archive",
        ops_low,
        None,
        &big,
        HOUR,
        2,
    )?;
    rec(
        &mut rsp,
        "detour-needs-3-hops-of-2",
        "ground-ops",
        "-",
        &now,
        wire(&tight)?,
        "reject:HopLimitExceeded",
    );

    rsp.section("label-rules");
    // (name, source, destination, label, sealed to, expected verdict)
    type Case<'a> = (&'a str, &'a str, &'a str, &'a str, Option<&'a str>, &'a str);
    let cases: [Case<'_>; 9] = [
        (
            "blp-destination-clearance",
            "ground-ops",
            "space-segment",
            "conf=high integ=high avail=high comp=tt-c",
            Some("space-segment"),
            "reject:ConfidentialityExceedsDestination",
        ),
        (
            "biba-integrity-floor",
            "ground-ops",
            "space-segment",
            "conf=moderate integ=low avail=high comp=tt-c",
            Some("space-segment"),
            "reject:IntegrityBelowFloor",
        ),
        (
            "destination-requires-sealing",
            "ground-ops",
            "space-segment",
            "conf=low integ=high avail=high comp=tt-c",
            None,
            "reject:EncryptionRequired",
        ),
        (
            "moderate-requires-sealing",
            "ground-ops",
            "relay-alpha",
            "conf=moderate integ=moderate avail=high comp=tt-c",
            None,
            "reject:EncryptionRequired",
        ),
        (
            "lab-not-cleared",
            "ground-ops",
            "science-lab",
            "conf=moderate integ=moderate avail=low comp=science",
            Some("science-lab"),
            "reject:ConfidentialityExceedsDestination",
        ),
        (
            "compartment",
            "ground-ops",
            "science-lab",
            "conf=low integ=moderate avail=low comp=ops",
            None,
            "reject:CompartmentNotPermitted",
        ),
        (
            "no-inbound-route",
            "ground-ops",
            "quarantine",
            "conf=low integ=low avail=low",
            None,
            "reject:NoRoute",
        ),
        (
            "sealed-to-wrong-domain",
            "ground-ops",
            "space-segment",
            tc,
            Some("relay-alpha"),
            "reject:SealedToWrongRecipient",
        ),
        (
            "source-not-cleared",
            "science-lab",
            "archive",
            "conf=moderate integ=moderate avail=low comp=science",
            Some("archive"),
            "reject:ConfidentialityExceedsSource",
        ),
    ];
    for (name, src, dst, label, seal, expect) in cases {
        let env = lab.send(src, dst, label, seal, b"label test")?;
        rec(&mut rsp, name, src, "-", &now, wire(&env)?, expect);
    }
    let vouch = lab.send(
        "quarantine",
        "ground-ops",
        "conf=low integ=moderate avail=low",
        None,
        b"x",
    )?;
    rec(
        &mut rsp,
        "source-cannot-vouch",
        "quarantine",
        "-",
        &now,
        wire(&vouch)?,
        "reject:IntegrityExceedsSource",
    );
    let (long, _) = lab.make(
        ground,
        "ground-ops",
        "relay-alpha",
        "conf=low integ=moderate avail=high comp=tt-c",
        None,
        b"x",
        48 * HOUR,
        8,
    )?;
    rec(
        &mut rsp,
        "lifetime-over-24h",
        "ground-ops",
        "-",
        &now,
        wire(&long)?,
        "reject:LifetimeTooLong",
    );

    rsp.section("authenticity");
    let ok = lab.send(
        "ground-ops",
        "relay-alpha",
        "conf=low integ=moderate avail=high comp=tt-c",
        None,
        b"status ok",
    )?;
    let mut tampered = ok.clone();
    tampered.payload = b"status OK".to_vec();
    rec(
        &mut rsp,
        "tampered",
        "ground-ops",
        "-",
        &now,
        wire(&tampered)?,
        "reject:BadSignature",
    );
    let rogue = SigningKey::from_seed(&[0xee; 32])?;
    let (unknown, _) = lab.make(
        &rogue,
        "ground-ops",
        "relay-alpha",
        "conf=low integ=moderate avail=high",
        None,
        b"x",
        HOUR,
        8,
    )?;
    rec(
        &mut rsp,
        "unknown-signer",
        "ground-ops",
        "-",
        &now,
        wire(&unknown)?,
        "reject:UnknownSigner",
    );
    let (spoof, _) = lab.make(
        &lab.key("science-lab")?.signing,
        "ground-ops",
        "relay-alpha",
        "conf=low integ=moderate avail=high",
        None,
        b"x",
        HOUR,
        8,
    )?;
    rec(
        &mut rsp,
        "spoofed-source",
        "ground-ops",
        "-",
        &now,
        wire(&spoof)?,
        "reject:SignerNotAuthorized",
    );
    rec(
        &mut rsp,
        "malformed",
        "ground-ops",
        "-",
        &now,
        "00".into(),
        "reject:Malformed",
    );
    let mut inflated = ok.clone();
    inflated.hops = 9;
    rec(
        &mut rsp,
        "hop-count-inflated",
        "ground-ops",
        "-",
        &now,
        wire(&inflated)?,
        "reject:HopCountInflated",
    );
    rec(
        &mut rsp,
        "no-edge-from-sender",
        "space-segment",
        "ground-ops",
        &now,
        wire(&up)?,
        "reject:UnexpectedArrival",
    );
    rec(
        &mut rsp,
        "foreign-origin",
        "relay-alpha",
        "-",
        &now,
        wire(&ok)?,
        "reject:UnexpectedArrival",
    );

    rsp.section("freshness");
    let late = (T0 + HOUR + 120_000 + 1).to_string();
    let early = (T0 - 120_001).to_string();
    rec(
        &mut rsp,
        "expired-beyond-skew",
        "ground-ops",
        "-",
        &late,
        wire(&ok)?,
        "reject:Expired",
    );
    rec(
        &mut rsp,
        "created-beyond-skew",
        "ground-ops",
        "-",
        &early,
        wire(&ok)?,
        "reject:NotYetValid",
    );
    rec(
        &mut rsp,
        "within-skew",
        "ground-ops",
        "-",
        &(T0 - 119_000).to_string(),
        wire(&ok)?,
        "forward:relay-alpha",
    );

    rsp.section("replay");
    rec(
        &mut rsp,
        "first-copy",
        "ground-ops",
        "-",
        &now,
        wire(&ok)?,
        "forward:relay-alpha",
    );
    rec(
        &mut rsp,
        "second-copy",
        "ground-ops",
        "-",
        &now,
        wire(&ok)?,
        "reject:Replay",
    );

    rsp.section("rate-limit");
    for (i, expect) in [
        "forward:ground-ops",
        "forward:ground-ops",
        "reject:RateLimited",
    ]
    .iter()
    .enumerate()
    {
        let env = lab.send(
            "archive",
            "ground-ops",
            "conf=low integ=high avail=low",
            None,
            format!("burst {i}").as_bytes(),
        )?;
        rec(
            &mut rsp,
            &format!("burst-{i}"),
            "archive",
            "-",
            &now,
            wire(&env)?,
            expect,
        );
    }
    let refill = lab.send(
        "archive",
        "ground-ops",
        "conf=low integ=high avail=low",
        None,
        b"after refill",
    )?;
    rec(
        &mut rsp,
        "one-second-later",
        "archive",
        "-",
        &(T0 + 2_000).to_string(),
        wire(&refill)?,
        "forward:ground-ops",
    );
    Ok(rsp.0)
}
