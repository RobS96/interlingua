//! Policy, label, keyring and audit-chain parsers never panic on any text.
#![no_main]

use interlingua::{Keyring, Label, Policy, audit};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = Policy::parse(&text);
    let _ = Label::parse(&text);
    let _ = Keyring::parse(&text);
    let _ = audit::verify_chain(&text);
});
