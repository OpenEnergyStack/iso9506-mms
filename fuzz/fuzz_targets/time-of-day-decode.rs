#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use mms::*;

fuzz_target!(|data: &[u8]| {
    let fp = TimeOfDay(Bytes::copy_from_slice(data));
    let _ = TimeOrDate::try_from(&fp);
});
