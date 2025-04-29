//! Implementation of ISO-9506 Manufacturing Message Specification
//! BER encoding and decoding of application layer PDUs.

use std::{fmt, io, str};

use bytes::{Buf, BufMut, BytesMut};
use chrono::{Days, NaiveDate, NaiveDateTime, NaiveTime, ParseError};
use num_enum::TryFromPrimitive;

use crate::messages::iso_9506_mms_1::{FloatingPoint, TimeOfDay};

/// Integer mappings for ObjectClass (from ISO-9506-MMS-1.asn)
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
#[allow(unused)]
pub enum ObjectClassValue {
    NamedVariable = 0,
    ScatteredAccess = 1,
    NamedVariableList = 2,
    NamedType = 3,
    Semaphore = 4,
    EventCondition = 5,
    EventAction = 6,
    EventEnrollment = 7,
    Journal = 8,
    Domain = 9,
    ProgramInvocation = 10,
    OperatorStation = 11,
}

/// Integer mappings for DataAccessError (from ISO-9506-MMS-1.asn)
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
#[allow(unused)]
pub enum DataAccessErrorValue {
    ObjectInvalidated = 0,
    HardwareFault = 1,
    TemporarilyUnavailable = 2,
    ObjectAccessDenied = 3,
    ObjectUndefined = 4,
    InvalidAddress = 5,
    TypeUnsupported = 6,
    TypeInconsistent = 7,
    ObjectAttributeInconsistent = 8,
    ObjectAccessUnsupported = 9,
    ObjectNonExistent = 10,
    ObjectValueInvalid = 11,
}

/// Bit mappings for MMS ParameterSupportOptions (from ISO-9506-MMS-Object-Module-1.asn)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(unused)]
pub enum ParameterSupportOptionsBit {
    Str1 = 0,
    Str2 = 1,
    Vnam = 2,
    Valt = 3,
    Vadr = 4,
    Vsca = 5,
    Tpy = 6,
    Vlis = 7,
    Cei = 10,
}

/// Bit mappings for MMS ServiceSupportOptions (from ISO-9506-MMS-Object-Module-1.asn)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(unused)]
pub enum ServiceSupportOptionsBit {
    Status = 0,
    GetNameList = 1,
    Identify = 2,
    Rename = 3,
    Read = 4,
    Write = 5,
    GetVariableAccessAttributes = 6,
    DefineNamedVariable = 7,
    DefineScatteredAccess = 8,
    GetScatteredAccessAttributes = 9,
    DeleteVariableAccess = 10,
    DefineNamedVariableList = 11,
    GetNamedVariableListAttributes = 12,
    DeleteNamedVariableList = 13,
    DefineNamedType = 14,
    GetNamedTypeAttributes = 15,
    DeleteNamedType = 16,
    Input = 17,
    Output = 18,
    TakeControl = 19,
    RelinquishControl = 20,
    DefineSemaphore = 21,
    DeleteSemaphore = 22,
    ReportSemaphoreStatus = 23,
    ReportPoolSemaphoreStatus = 24,
    ReportSemaphoreEntryStatus = 25,
    InitiateDownloadSequence = 26,
    DownloadSegment = 27,
    TerminateDownloadSequence = 28,
    InitiateUploadSequence = 29,
    UploadSegment = 30,
    TerminateUploadSequence = 31,
    RequestDomainDownload = 32,
    RequestDomainUpload = 33,
    LoadDomainContent = 34,
    StoreDomainContent = 35,
    DeleteDomain = 36,
    GetDomainAttributes = 37,
    CreateProgramInvocation = 38,
    DeleteProgramInvocation = 39,
    Start = 40,
    Stop = 41,
    Resume = 42,
    Reset = 43,
    Kill = 44,
    GetProgramInvocationAttributes = 45,
    ObtainFile = 46,
    DefineEventCondition = 47,
    DeleteEventCondition = 48,
    GetEventConditionAttributes = 49,
    ReportEventConditionStatus = 50,
    AlterEventConditionMonitoring = 51,
    TriggerEvent = 52,
    DefineEventAction = 53,
    DeleteEventAction = 54,
    GetEventActionAttributes = 55,
    ReportEventActionStatus = 56,
    DefineEventEnrollment = 57,
    DeleteEventEnrollment = 58,
    AlterEventEnrollment = 59,
    ReportEventEnrollmentStatus = 60,
    GetEventEnrollmentAttributes = 61,
    AcknowledgeEventNotification = 62,
    GetAlarmSummary = 63,
    GetAlarmEnrollmentSummary = 64,
    ReadJournal = 65,
    WriteJournal = 66,
    InitializeJournal = 67,
    ReportJournalStatus = 68,
    CreateJournal = 69,
    DeleteJournal = 70,
    GetCapabilityList = 71,
    FileOpen = 72,
    FileRead = 73,
    FileClose = 74,
    FileRename = 75,
    FileDelete = 76,
    FileDirectory = 77,
    UnsolicitedStatus = 78,
    InformationReport = 79,
    EventNotification = 80,
    AttachToEventCondition = 81,
    AttachToSemaphore = 82,
    Conclude = 83,
    Cancel = 84,
}

/// Create a bitmask from bit offsets. Accepts any argument that can be cast to `usize`.
///
/// # Example
/// ```
/// use mms::bitstring;
/// use rasn::prelude::*;
///
/// let mask: FixedBitString<8> = bitstring!(0, 2, 7);
/// ```
#[macro_export]
macro_rules! bitstring {
    ( $( $x:expr ),* ) => {
        {
            let mut mask = rasn::types::FixedBitString::ZERO;
            $(
                mask.set($x as usize, true);
            )*
            mask
        }
    };
}

/// Convert from MMS variable length `FloatingPoint` to an `f64`.
/// See [ISO 9506-2:2003 Section 14.4.2.2]
///
/// N = Number of exponent bits
/// S = Sign bit
/// E = Exponent
/// M = Mantissa
///
/// ```text
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |       N       |S| Variable: E[9..(N+9)] and M[(N+9)..]      ...
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// When E == 0:
///   V = -1^S * F * 2**(2 - 2^(N-1))
/// Otherwise:
///   V = -1^S * (1+F) * 2**(E - 2^(N-1) + 1)
///
/// Note that this conversion function supports floating point representations
/// that align with IEEE 754 binary32 and binary64 and rejects other less
/// common representations.
impl TryFrom<&FloatingPoint> for f64 {
    type Error = io::Error;

    fn try_from(value: &FloatingPoint) -> Result<Self, Self::Error> {
        let mut bytes = &value.0[..];

        let exp = bytes
            .try_get_u8()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "FloatingPoint must be at least 2 bytes"))?;
        let len = bytes.len();

        match (len, exp) {
            // IEEE 754 binary32
            (4, 8) => Ok(bytes.get_f32() as f64),

            // IEEE 754 binary64
            (8, 11) => Ok(bytes.get_f64()),

            // Unsupported representation
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{len} byte FloatingPoint with {exp} bit exponent not representable as IEEE 754",),
            )),
        }
    }
}

/// Convert from f32 to MMS variable length `FloatingPoint`.
/// See [ISO 9506-2:2003 Section 14.4.2.2]
impl From<f32> for FloatingPoint {
    fn from(value: f32) -> FloatingPoint {
        let mut buf = BytesMut::new();

        buf.put_u8(8);
        buf.put_f32(value);

        FloatingPoint(buf.freeze())
    }
}

/// Convert from f64 to MMS variable length `FloatingPoint`.
/// See [ISO 9506-2:2003 Section 14.4.2.2]
impl From<f64> for FloatingPoint {
    fn from(value: f64) -> FloatingPoint {
        let mut buf = BytesMut::new();

        buf.put_u8(11);
        buf.put_f64(value);

        FloatingPoint(buf.freeze())
    }
}

/// The MMS `TimeOfDay` epoch is January 1, 1984 [ISO 9506-2:2003 Section 7.5.1]
const TIME_OF_DAY_EPOCH: NaiveDateTime = NaiveDate::from_yo_opt(1984, 1).unwrap().and_hms_opt(0, 0, 0).unwrap();

/// Wrapper type for both `TimeOfDay` variants.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TimeOrDate {
    Time(NaiveTime),
    DateTime(NaiveDateTime),
}

/// Display a `TimeOrDate` using the underlying [chrono::NaiveTime::fmt] and
/// [chrono::NaiveDateTime::fmt] display formatter.
impl fmt::Display for TimeOrDate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TimeOrDate::Time(t) => t.fmt(f),
            TimeOrDate::DateTime(dt) => dt.fmt(f),
        }
    }
}

/// Parse a `TimeOrDate` using the underlying [chrono::NaiveTime::from_str] and
/// [chrono::NaiveDateTime::from_str] parsers.
impl str::FromStr for TimeOrDate {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<TimeOrDate, ParseError> {
        // First try to match a full date and time
        match NaiveDateTime::from_str(s) {
            Ok(dt) => Ok(TimeOrDate::DateTime(dt)),
            // If not a date and time, try to parse just time
            Err(err) => match NaiveTime::from_str(s) {
                Ok(t) => Ok(TimeOrDate::Time(t)),
                // If neither, return the original error
                Err(_) => Err(err),
            },
        }
    }
}

/// Convert from MMS `TimeOfDay` to a `chrono` type.
/// See [ISO 9506-2:2003 Section 7.5.1]
///
/// ```text
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |0 0 0 0|          28-bit time-of-day in milliseconds           |16-bit day from January 1, 1984|
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// MMS supports both a 4-byte time representation and a 6-byte date-time representation.
impl TryFrom<&TimeOfDay> for TimeOrDate {
    type Error = io::Error;

    fn try_from(value: &TimeOfDay) -> Result<Self, Self::Error> {
        let mut bytes = &value.0[..];

        match bytes.len() {
            4 | 6 => {
                let time_ms = bytes.get_u32() & 0x0fffffff; // Ignore 4 most significant bits (should always be 0)
                let time_s = time_ms / 1000;
                let time_ns = (time_ms % 1000) * 1_000_000;

                let time = NaiveTime::from_num_seconds_from_midnight_opt(time_s, time_ns).ok_or(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TimeOfDay time out of range",
                ))?;

                if bytes.is_empty() {
                    Ok(TimeOrDate::Time(time))
                } else {
                    let days = Days::new(bytes.get_u16() as u64);
                    let date = TIME_OF_DAY_EPOCH.date().checked_add_days(days).unwrap();

                    Ok(TimeOrDate::DateTime(date.and_time(time)))
                }
            }

            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} byte TimeOfDay is invalid: must be 4 or 6 bytes", bytes.len()),
            )),
        }
    }
}

/// Convert from TimeOrDate to MMS `TimeOfDay`.
/// See [ISO 9506-2:2003 Section 7.5.1]
impl TryFrom<TimeOrDate> for TimeOfDay {
    type Error = io::Error;

    fn try_from(value: TimeOrDate) -> Result<TimeOfDay, Self::Error> {
        let mut buf = BytesMut::new();

        match value {
            TimeOrDate::Time(time) => {
                buf.put_u32(time.signed_duration_since(NaiveTime::MIN).num_milliseconds() as u32);
            }

            TimeOrDate::DateTime(datetime) => {
                if datetime < TIME_OF_DAY_EPOCH {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "TimeOfDay cannot represent dates prior to 1984",
                    ));
                }

                buf.put_u32(datetime.time().signed_duration_since(NaiveTime::MIN).num_milliseconds() as u32);
                buf.put_u16(datetime.signed_duration_since(TIME_OF_DAY_EPOCH).num_days() as u16);
            }
        }

        Ok(TimeOfDay(buf.freeze()))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitvec::prelude::*;
    use rasn::{
        ber,
        types::{Integer, VisibleString},
    };

    use super::*;
    use crate::{
        bitstring,
        messages::{iso_9506_mms_1::*, mms_object_module_1::*},
    };

    #[test]
    fn bitstring_from_enum() {
        use rasn::types::FixedBitString;

        let mask: FixedBitString<2> = bitstring!(
            ParameterSupportOptionsBit::Str1,
            ParameterSupportOptionsBit::Vadr,
            ParameterSupportOptionsBit::Cei
        );

        assert_eq!(mask, FixedBitString::new([0b10001000, 0b00100000]))
    }

    #[test]
    fn bitstring_from_literal() {
        use rasn::types::FixedBitString;

        let mask: FixedBitString<3> = bitstring!(0, 4, 17);

        assert_eq!(mask, FixedBitString::new([0b10001000, 0b00000000, 0b01000000]))
    }

    #[test]
    fn floating_point() {
        let valid32 = FloatingPoint({
            let mut bytes = BytesMut::new();
            bytes.put_u8(8);
            bytes.put_f32(1.2345);
            bytes.freeze()
        });

        let valid64 = FloatingPoint({
            let mut bytes = BytesMut::new();
            bytes.put_u8(11);
            bytes.put_f64(-1234.56789);
            bytes.freeze()
        });

        let unsupported_length = FloatingPoint({
            let mut bytes = BytesMut::new();
            bytes.put_u8(8);
            bytes.put_f32(1.2345);
            bytes.put_u8(0);
            bytes.freeze()
        });

        let unsupported_exponent = FloatingPoint({
            let mut bytes = BytesMut::new();
            bytes.put_u8(9);
            bytes.put_f32(1.2345);
            bytes.freeze()
        });

        // Decode
        assert_eq!(f64::try_from(&valid32).unwrap(), 1.2345f32 as f64);
        assert_eq!(f64::try_from(&valid64).unwrap(), -1234.56789);
        assert!(f64::try_from(&unsupported_length).is_err());
        assert!(f64::try_from(&unsupported_exponent).is_err());

        // Encode
        assert_eq!(FloatingPoint::from(1.2345f32), valid32);
        assert_eq!(FloatingPoint::from(-1234.56789), valid64);
    }

    #[test]
    fn time_of_day() {
        let time_min = TimeOrDate::Time(NaiveTime::from_hms_opt(0, 0, 0).unwrap());
        let time_max = TimeOrDate::Time(NaiveTime::from_hms_milli_opt(23, 59, 59, 999).unwrap());
        let time_date = TimeOrDate::DateTime(NaiveDateTime::new(
            NaiveDate::from_ymd_opt(1997, 8, 29).unwrap(),
            NaiveTime::from_hms_milli_opt(9, 14, 19, 910).unwrap(),
        ));

        let valid_time_min = TimeOfDay({
            let mut bytes = BytesMut::new();
            bytes.put_u32(0); // 00:00:00.000
            bytes.freeze()
        });

        let valid_time_max = TimeOfDay({
            let mut bytes = BytesMut::new();
            bytes.put_u32(24 * 60 * 60 * 1000 - 1); // 23:59:59.999
            bytes.freeze()
        });

        let valid_time_date = TimeOfDay({
            let mut bytes = BytesMut::new();
            bytes.put_u32((((((9 * 60) + 14) * 60) + 19) * 1000) + 910); // 09:14:19.91
            bytes.put_u16(4989); // August 29, 1997
            bytes.freeze()
        });

        let invalid_length = TimeOfDay({
            let mut bytes = BytesMut::new();
            bytes.put_u32(0);
            bytes.put_u8(0);
            bytes.freeze()
        });

        let invalid_time = TimeOfDay({
            let mut bytes = BytesMut::new();
            bytes.put_u32(24 * 60 * 60 * 1000); // 24:00:00.000
            bytes.freeze()
        });

        // Decode
        assert_eq!(TimeOrDate::try_from(&valid_time_min).unwrap(), time_min);
        assert_eq!(TimeOrDate::try_from(&valid_time_max).unwrap(), time_max);
        assert_eq!(TimeOrDate::try_from(&valid_time_date).unwrap(), time_date);
        assert!(TimeOrDate::try_from(&invalid_length).is_err());
        assert!(TimeOrDate::try_from(&invalid_time).is_err());

        // Encode
        assert_eq!(TimeOfDay::try_from(time_max).unwrap(), valid_time_max);
        assert_eq!(TimeOfDay::try_from(time_date).unwrap(), valid_time_date);

        // To String
        assert_eq!(format!("{time_max}"), "23:59:59.999");
        assert_eq!(format!("{time_date}"), "1997-08-29 09:14:19.910");

        // From String
        assert_eq!(TimeOrDate::from_str("23:59:59.999"), Ok(time_max));
        assert_eq!(TimeOrDate::from_str("1997-08-29T09:14:19.910"), Ok(time_date));
        assert!(TimeOrDate::from_str("23-59:59.999").is_err());
        assert!(TimeOrDate::from_str("1997-08T09:14:19.910").is_err());
        assert!(TimeOrDate::from_str("nope").is_err());
    }

    // Test vectors derived from public Wireshark captures:
    // https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/mms.pcap.gz

    #[test]
    fn initiate_request() {
        let pdu = MMSpdu::initiate_RequestPDU(InitiateRequestPDU {
            local_detail_calling: Some(Integer32(32000)),
            proposed_max_serv_outstanding_called: Integer16(20),
            proposed_max_serv_outstanding_calling: Integer16(20),
            proposed_data_structure_nesting_level: Some(Integer8(4)),
            init_request_detail: InitiateRequestPDUInitRequestDetail {
                proposed_version_number: Integer16(1),
                proposed_parameter_cbb: ParameterSupportOptions(bitstring!(
                    ParameterSupportOptionsBit::Str1,
                    ParameterSupportOptionsBit::Str2,
                    ParameterSupportOptionsBit::Vnam,
                    ParameterSupportOptionsBit::Valt,
                    ParameterSupportOptionsBit::Vadr,
                    ParameterSupportOptionsBit::Tpy,
                    ParameterSupportOptionsBit::Vlis
                )),
                services_supported_calling: ServiceSupportOptions(bitstring!(
                    ServiceSupportOptionsBit::GetNameList,
                    ServiceSupportOptionsBit::Identify,
                    ServiceSupportOptionsBit::Read,
                    ServiceSupportOptionsBit::Write,
                    ServiceSupportOptionsBit::GetVariableAccessAttributes,
                    ServiceSupportOptionsBit::DefineNamedVariableList,
                    ServiceSupportOptionsBit::GetNamedVariableListAttributes,
                    ServiceSupportOptionsBit::DeleteNamedVariableList,
                    ServiceSupportOptionsBit::GetNamedTypeAttributes,
                    ServiceSupportOptionsBit::DefineEventEnrollment,
                    ServiceSupportOptionsBit::DeleteEventEnrollment,
                    ServiceSupportOptionsBit::GetEventEnrollmentAttributes,
                    ServiceSupportOptionsBit::InformationReport,
                    ServiceSupportOptionsBit::EventNotification,
                    ServiceSupportOptionsBit::Conclude,
                    ServiceSupportOptionsBit::Cancel
                )),
            },
        });

        let expected =
            hex::decode("a82580027d00810114820114830104a416800101810305fb00820c036e1d000000000064000198").unwrap();

        let encoded = ber::encode(&pdu).unwrap();
        assert_eq!(expected, encoded);

        let pdu2: MMSpdu = ber::decode(&expected).unwrap();
        assert_eq!(pdu, pdu2);
    }

    #[test]
    fn initiate_response() {
        let pdu = MMSpdu::initiate_ResponsePDU(InitiateResponsePDU {
            local_detail_called: Some(Integer32(32000)),
            negotiated_max_serv_outstanding_calling: Integer16(20),
            negotiated_max_serv_outstanding_called: Integer16(20),
            negotiated_data_structure_nesting_level: Some(Integer8(4)),
            init_response_detail: InitiateResponsePDUInitResponseDetail {
                negotiated_version_number: Integer16(1),
                negotiated_parameter_cbb: ParameterSupportOptions(bitstring!(
                    ParameterSupportOptionsBit::Str1,
                    ParameterSupportOptionsBit::Str2,
                    ParameterSupportOptionsBit::Vnam,
                    ParameterSupportOptionsBit::Valt,
                    ParameterSupportOptionsBit::Vadr,
                    ParameterSupportOptionsBit::Tpy,
                    ParameterSupportOptionsBit::Vlis
                )),
                services_supported_called: ServiceSupportOptions(bitstring!(
                    ServiceSupportOptionsBit::GetNameList,
                    ServiceSupportOptionsBit::Identify,
                    ServiceSupportOptionsBit::Read,
                    ServiceSupportOptionsBit::Write,
                    ServiceSupportOptionsBit::GetVariableAccessAttributes,
                    ServiceSupportOptionsBit::DefineNamedVariableList,
                    ServiceSupportOptionsBit::GetNamedVariableListAttributes,
                    ServiceSupportOptionsBit::DeleteNamedVariableList,
                    ServiceSupportOptionsBit::GetNamedTypeAttributes,
                    ServiceSupportOptionsBit::DefineEventEnrollment,
                    ServiceSupportOptionsBit::DeleteEventEnrollment,
                    ServiceSupportOptionsBit::GetEventEnrollmentAttributes,
                    ServiceSupportOptionsBit::InformationReport,
                    ServiceSupportOptionsBit::EventNotification,
                    ServiceSupportOptionsBit::Conclude,
                    ServiceSupportOptionsBit::Cancel
                )),
            },
        });

        let expected =
            hex::decode("a92580027d00810114820114830104a416800101810305fb00820c036e1d000000000064000198").unwrap();

        let encoded = ber::encode(&pdu).unwrap();
        assert_eq!(expected, encoded);

        let pdu2: MMSpdu = ber::decode(&expected).unwrap();
        assert_eq!(pdu, pdu2);
    }

    #[test]
    fn identify_request() {
        let pdu = MMSpdu::confirmed_RequestPDU(ConfirmedRequestPDU {
            invoke_id: Unsigned32(4431),
            list_of_modifiers: None,
            service: ConfirmedServiceRequest::identify(IdentifyRequest(())),
        });

        let expected = hex::decode("a0060202114f8200").unwrap();

        let encoded = ber::encode(&pdu).unwrap();
        assert_eq!(expected, encoded);

        let pdu2: MMSpdu = ber::decode(&expected).unwrap();
        assert_eq!(pdu, pdu2);
    }

    #[test]
    fn identify_response() {
        let pdu = MMSpdu::confirmed_ResponsePDU(ConfirmedResponsePDU {
            invoke_id: Unsigned32(4431),
            service: ConfirmedServiceResponse::identify(IdentifyResponse {
                vendor_name: MMSString(VisibleString::try_from("Verrus Inc.").unwrap()),
                model_name: MMSString(VisibleString::try_from("Unit Test 9000").unwrap()),
                revision: MMSString(VisibleString::try_from("1.2.3").unwrap()),
                list_of_abstract_syntaxes: None,
            }),
        });

        let expected =
            hex::decode("a12a0202114fa224800b56657272757320496e632e810e556e6974205465737420393030308205312e322e33")
                .unwrap();

        let encoded = ber::encode(&pdu).unwrap();
        assert_eq!(expected, encoded);

        let pdu2: MMSpdu = ber::decode(&expected).unwrap();
        assert_eq!(pdu, pdu2);
    }

    #[test]
    fn read_request() {
        let pdu = MMSpdu::confirmed_RequestPDU(ConfirmedRequestPDU {
            invoke_id: Unsigned32(4432),
            list_of_modifiers: None,
            service: ConfirmedServiceRequest::read(ReadRequest {
                specification_with_result: false,
                variable_access_specification: VariableAccessSpecification::listOfVariable(
                    VariableAccessSpecificationListOfVariable(vec![
                        AnonymousVariableAccessSpecificationListOfVariable {
                            variable_specification: VariableSpecification::name(ObjectName::domain_specific(
                                ObjectNameDomainSpecific {
                                    domain_id: Identifier(VisibleString::try_from("KIRKLAND").unwrap()),
                                    item_id: Identifier(VisibleString::try_from("Bilateral_Table_ID").unwrap()),
                                },
                            )),
                            alternate_access: None,
                        },
                    ]),
                ),
            }),
        });

        let expected = hex::decode(
            "a02e02021150a428a126a0243022a020a11e1a084b49524b4c414e441a1242696c61746572616c5f5461626c655f4944",
        )
        .unwrap();

        let encoded = ber::encode(&pdu).unwrap();
        assert_eq!(expected, encoded);

        let pdu2: MMSpdu = ber::decode(&expected).unwrap();
        assert_eq!(pdu, pdu2);
    }

    #[test]
    fn read_response() {
        let pdu = MMSpdu::confirmed_ResponsePDU(ConfirmedResponsePDU {
            invoke_id: Unsigned32(4432),
            service: ConfirmedServiceResponse::read(ReadResponse {
                variable_access_specification: None,
                list_of_access_result: vec![AccessResult::success(Data::visible_string(
                    VisibleString::try_from("1.0").unwrap(),
                ))],
            }),
        });

        let expected = hex::decode("a10d02021150a407a1058a03312e30").unwrap();

        let encoded = ber::encode(&pdu).unwrap();
        assert_eq!(expected, encoded);

        let pdu2: MMSpdu = ber::decode(&expected).unwrap();
        assert_eq!(pdu, pdu2);
    }

    #[test]
    fn write_request() {
        let pdu = MMSpdu::confirmed_RequestPDU(ConfirmedRequestPDU {
            invoke_id: Unsigned32(4439),
            list_of_modifiers: None,
            service: ConfirmedServiceRequest::write(WriteRequest {
                variable_access_specification: VariableAccessSpecification::listOfVariable(
                    VariableAccessSpecificationListOfVariable(vec![
                        AnonymousVariableAccessSpecificationListOfVariable {
                            variable_specification: VariableSpecification::name(ObjectName::domain_specific(
                                ObjectNameDomainSpecific {
                                    domain_id: Identifier(VisibleString::try_from("KIRKLAND").unwrap()),
                                    item_id: Identifier(VisibleString::try_from("CITEC_TS1").unwrap()),
                                },
                            )),
                            alternate_access: None,
                        },
                    ]),
                ),
                list_of_data: vec![Data::structure(vec![
                    Data::structure(vec![
                        Data::unsigned(Integer::from(1)),
                        Data::visible_string(VisibleString::try_from("KIRKLAND").unwrap()),
                        Data::visible_string(VisibleString::try_from("EMS_STATUS_ICCP_IN").unwrap()),
                    ]),
                    Data::integer(Integer::from(0)),
                    Data::integer(Integer::from(0)),
                    Data::integer(Integer::from(0)),
                    Data::integer(Integer::from(1)),
                    Data::integer(Integer::from(0)),
                    Data::bit_string(bitvec![u8, Msb0; 0, 0, 1, 0, 0]),
                    Data::boolean(false),
                    Data::boolean(false),
                    Data::boolean(true),
                    Data::boolean(true),
                    Data::integer(Integer::from(0)),
                ])],
            }),
        });

        let expected =
        hex::decode("a06c02021157a566a01b3019a017a1151a084b49524b4c414e441a0943495445435f545331a047a245a2218601018a084b49524b4c414e448a12454d535f5354415455535f494343505f494e850100850100850100850101850100840203208301008301008301ff8301ff850100")
            .unwrap();

        let encoded = ber::encode(&pdu).unwrap();
        assert_eq!(expected, encoded);

        let pdu2: MMSpdu = ber::decode(&expected).unwrap();
        assert_eq!(pdu, pdu2);
    }

    #[test]
    fn write_response() {
        let pdu = MMSpdu::confirmed_ResponsePDU(ConfirmedResponsePDU {
            invoke_id: Unsigned32(4439),
            service: ConfirmedServiceResponse::write(WriteResponse(vec![AnonymousWriteResponse::success(())])),
        });

        let expected = hex::decode("a10802021157a5028100").unwrap();

        let encoded = ber::encode(&pdu).unwrap();
        assert_eq!(expected, encoded);

        let pdu2: MMSpdu = ber::decode(&expected).unwrap();
        assert_eq!(pdu, pdu2);
    }

    #[test]
    fn get_name_list_request() {
        let pdu = MMSpdu::confirmed_RequestPDU(ConfirmedRequestPDU {
            invoke_id: Unsigned32(4433),
            list_of_modifiers: None,
            service: ConfirmedServiceRequest::getNameList(GetNameListRequest {
                object_class: ObjectClass::basicObjectClass(2),
                object_scope: GetNameListRequestObjectScope::domainSpecific(Identifier(
                    VisibleString::try_from("KIRKLAND").unwrap(),
                )),
                continue_after: None,
            }),
        });

        let expected = hex::decode("a01702021151a111a003800102a10a81084b49524b4c414e44").unwrap();

        let encoded = ber::encode(&pdu).unwrap();
        assert_eq!(expected, encoded);

        let pdu2: MMSpdu = ber::decode(&expected).unwrap();
        assert_eq!(pdu, pdu2);
    }

    #[test]
    fn get_name_list_response() {
        let pdu = MMSpdu::confirmed_ResponsePDU(ConfirmedResponsePDU {
            invoke_id: Unsigned32(4433),
            service: ConfirmedServiceResponse::getNameList(GetNameListResponse {
                list_of_identifier: vec![
                    Identifier(VisibleString::try_from("EMS_ANALOG_ICCP_IN").unwrap()),
                    Identifier(VisibleString::try_from("EMS_STATUS_ICCP_IN").unwrap()),
                ],
                more_follows: false,
            }),
        });

        let expected = hex::decode(
        "a13302021151a12da0281a12454d535f414e414c4f475f494343505f494e1a12454d535f5354415455535f494343505f494e810100").unwrap();

        let encoded = ber::encode(&pdu).unwrap();
        assert_eq!(expected, encoded);

        let pdu2: MMSpdu = ber::decode(&expected).unwrap();
        assert_eq!(pdu, pdu2);
    }
}
