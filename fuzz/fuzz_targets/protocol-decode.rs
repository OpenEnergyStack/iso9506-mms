#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use mms::protocol;

fuzz_target!(|data: &[u8]| {
    let buf = Bytes::copy_from_slice(data);
    let mut params = protocol::ProtocolParams::default();
    let _ = protocol::decode(buf, &mut params);
});
