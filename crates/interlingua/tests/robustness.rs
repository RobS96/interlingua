//! Property tests without extra crates: a fixed-seed generator throws random
//! and mutated inputs at every decoder and checks the invariants that matter
//! for a router facing hostile input. cargo-fuzz targets in `fuzz/` explore
//! the same surfaces with coverage guidance in CI.
//!
//! Invariants:
//! * no decoder panics, whatever the bytes;
//! * whatever the CBOR decoder accepts re-encodes to the same bytes;
//! * a bit flip anywhere in a signed envelope is never accepted as valid;
//! * the router answers every input with exactly one audit line.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use interlingua::ccsds::{self, SpacePacket};
use interlingua::envelope::{Draft, seal_and_sign};
use interlingua::{Envelope, Keyring, Label, Policy, Router, SecretKeys, cbor};

/// SplitMix64: tiny, deterministic, good enough to drive mutations.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n.max(1)).unwrap()).unwrap()
    }

    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = self.below(max + 1);
        (0..len).map(|_| self.next().to_le_bytes()[0]).collect()
    }

    fn mutate(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = input.to_vec();
        for _ in 0..=self.below(4) {
            match self.below(4) {
                0 if !out.is_empty() => {
                    let i = self.below(out.len());
                    out[i] ^= 1 << self.below(8);
                }
                1 if !out.is_empty() => {
                    let i = self.below(out.len());
                    out[i] = self.next().to_le_bytes()[0];
                }
                2 if !out.is_empty() => {
                    let i = self.below(out.len());
                    out.truncate(i);
                }
                _ => {
                    let i = self.below(out.len() + 1);
                    out.insert(i, self.next().to_le_bytes()[0]);
                }
            }
        }
        out
    }
}

const CBOR_SEEDS: &[&[u8]] = &[
    b"\xa2\x61\x61\x01\x61\x62\x82\x02\x03",
    b"\x83\x01\x82\x02\x03\x82\x04\x05",
    b"\xfb\x7e\x37\xe4\x3c\x88\x00\x75\x9c",
    b"\xf9\x7e\x00",
    b"\x64\xf0\x90\x85\x91",
];

#[test]
fn cbor_decoder_never_panics_and_round_trips() {
    let mut rng = Rng(0x1d1e_5eed);
    let mut accepted = 0;
    for i in 0..100_000 {
        let input = if i % 2 == 0 {
            rng.bytes(64)
        } else {
            let seed = CBOR_SEEDS[rng.below(CBOR_SEEDS.len())];
            rng.mutate(seed)
        };
        if let Ok(value) = cbor::decode(&input) {
            accepted += 1;
            assert_eq!(
                cbor::encode(&value).unwrap(),
                input,
                "accepted input must be canonical"
            );
            let _ = cbor::diag(&value);
        }
    }
    assert!(
        accepted > 1_000,
        "the generator should reach valid CBOR too ({accepted})"
    );
}

#[test]
fn other_parsers_never_panic() {
    let mut rng = Rng(0xcc5d5);
    for _ in 0..30_000 {
        let input = rng.bytes(96);
        let _ = SpacePacket::decode(&input);
        let _ = ccsds::deframe(&input, 4096);
        let text = String::from_utf8_lossy(&input);
        let _ = Label::parse(&text);
        let _ = Policy::parse(&text);
        let _ = Keyring::parse(&text);
        let _ = interlingua::audit::verify_chain(&text);
        let _ = Envelope::decode(&input);
    }
}

#[test]
fn envelope_bit_flips_never_verify_and_router_always_audits() {
    let ground = SecretKeys::generate("ground-ops").unwrap();
    let mut ring = Keyring::new();
    ring.add(ground.public()).unwrap();
    let draft = Draft {
        src: "ground-ops",
        dst: "ground-ops",
        label: Label::parse("conf=low integ=low avail=low").unwrap(),
        content_type: "text/plain",
        ttl_ms: 60_000,
        max_hops: 1,
        payload: b"telemetry frame",
    };
    let now = 1_767_225_600_000;
    let wire = seal_and_sign(&draft, &ground.signing, None, now)
        .unwrap()
        .encode()
        .unwrap();
    let policy = Policy::parse(
        "policy version=1 name=p\ndomain name=ground-ops conf=low integ=low avail=low\n",
    )
    .unwrap();
    let router = Router::new(policy, ring.clone(), "ground-ops").unwrap();
    let mut rng = Rng(0xf11b);
    for _ in 0..300 {
        let mut bad = wire.clone();
        let i = rng.below(bad.len());
        bad[i] ^= 1 << rng.below(8);
        let verdict = Envelope::decode(&bad).and_then(|e| e.verify(&ring).map(|_| e));
        // The only bits outside the signature are the unprotected hop count:
        // flipping those can stay valid, so check that case explicitly.
        if let Ok(env) = verdict {
            let original = Envelope::decode(&wire).unwrap();
            assert_eq!(env.protected, original.protected);
            assert_eq!(env.payload, original.payload);
            assert_eq!(env.signature, original.signature);
        }
        let decision = router.route(&bad, None, now);
        assert!(decision.audit_line.starts_with("audit seq="));
    }
}
