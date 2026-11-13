//! CCSDS packet decoding and reassembly never panic and respect the size bound.
#![no_main]

use interlingua::ccsds::{self, SpacePacket};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((packet, used)) = SpacePacket::decode(data) {
        assert!(used <= data.len());
        assert_eq!(packet.encode().ok().as_deref(), data.get(..used));
    }
    if let Ok(message) = ccsds::deframe(data, 4096) {
        assert!(message.len() <= 4096);
    }
});
