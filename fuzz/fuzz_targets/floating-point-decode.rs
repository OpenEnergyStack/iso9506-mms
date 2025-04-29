#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use mms::*;

fuzz_target!(|data: &[u8]| {
    let fp = FloatingPoint(Bytes::copy_from_slice(data));
    let _ = f64::try_from(&fp);
});
