//! The router's whole decision path on hostile bytes: never panics, always
//! writes exactly one audit line, and never accepts what it cannot verify.
#![no_main]

use std::sync::OnceLock;

use interlingua::{Keyring, Policy, Router, SecretKeys};
use libfuzzer_sys::fuzz_target;

fn router() -> &'static Router {
    static ROUTER: OnceLock<Router> = OnceLock::new();
    ROUTER.get_or_init(|| {
        let mut ring = Keyring::new();
        for d in ["ground-ops", "relay"] {
            ring.add(SecretKeys::generate(d).expect("keygen").public()).expect("keyring");
        }
        let policy = Policy::parse(
            "policy version=1 name=fuzz\n\
             domain name=ground-ops conf=high integ=high avail=high comp=tt-c\n\
             domain name=relay conf=moderate integ=moderate avail=high comp=tt-c\n\
             route from=ground-ops to=relay bidirectional=yes\n",
        )
        .expect("policy");
        Router::new(policy, ring, "ground-ops").expect("router")
    })
}

fuzz_target!(|data: &[u8]| {
    let decision = router().route(data, Some("relay"), 1_767_225_600_000);
    assert!(decision.audit_line.starts_with("audit seq="));
    // Random bytes carry no valid ML-DSA-87 signature from the keyring.
    assert!(!decision.accepted(), "accepted an unverifiable envelope");
});
