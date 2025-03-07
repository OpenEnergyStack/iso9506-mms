//! Referenced object IDs not defined in schemas or other libraries

use lazy_static::lazy_static;
use rasn::types::ObjectIdentifier;

lazy_static! {
    // {iso(1) registration-authority(1) reserved(1)}
    pub static ref ISO_REGISTRATION_AUTHORITY_1: ObjectIdentifier = ObjectIdentifier::new(&[1, 1, 1]).unwrap();
}

lazy_static! {
    // {iso(1) registration-authority(1) document-type(2)}
    pub static ref ISO_REGISTRATION_AUTHORITY_2: ObjectIdentifier = ObjectIdentifier::new(&[1, 1, 2]).unwrap();
}

lazy_static! {
    // {joint-iso-itu-t(2) asn1(1) basic-encoding(1)}
    pub static ref BASIC_ENCODING: ObjectIdentifier = ObjectIdentifier::new(&[2, 1, 1]).unwrap();
}

lazy_static! {
    // {iso(1) standard(0) iso9506(9506) part2(2) mms-application-context-version1(5)}
    pub static ref MMS_APPLICATION_CONTEXT: ObjectIdentifier = ObjectIdentifier::new(&[1, 0, 9506, 2, 5]).unwrap();
}
