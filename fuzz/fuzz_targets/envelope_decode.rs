//! Envelope decoding: never panics; anything that decodes re-encodes and
//! decodes to the same envelope.
#![no_main]

use interlingua::Envelope;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = Envelope::decode(data) {
        let wire = env.encode().expect("a decoded envelope must re-encode");
        assert_eq!(Envelope::decode(&wire).expect("and decode again"), env);
        let _ = env.sealed_recipient();
        let _ = env.open(None);
    }
});
