#[allow(clippy::style)]
pub mod messages {
    // Import generated ASN.1 bindings
    include!(concat!(env!("OUT_DIR"), "/messages.rs"));
}

pub mod client;
pub mod protocol;

mod error;
mod oid;

// Re-export common types from generated ASN.1 bindings
pub use rasn::types::{
    Any, BitStr, BitString, BmpString, Constructed, Date, FixedBitString, FixedOctetString, GeneralString,
    GeneralizedTime, GraphicString, Ia5String, Integer, NumericString, ObjectIdentifier, OctetString, Oid,
    PrintableString, RealType, SequenceOf, SetOf, TeletexString, UniversalString, UtcTime, Utf8String, VisibleString,
};

pub use crate::{
    error::*,
    messages::{iso_9506_mms_1::*, iso_9506_mms_1_a::*, mms_object_module_1::*},
    protocol::mms::*,
};
