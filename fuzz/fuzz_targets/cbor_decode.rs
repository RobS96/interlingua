//! Strict CBOR: never panics, and whatever it accepts is canonical
//! (re-encoding gives back exactly the input).
#![no_main]

use interlingua::cbor;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = cbor::decode(data) {
        let again = cbor::encode(&value).expect("an accepted value must re-encode");
        assert_eq!(again, data, "accepted input was not canonical");
        let _ = cbor::diag(&value);
    }
});
