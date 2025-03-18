//! Implementation of ISO-9506 Manufacturing Message Specification
//! BER encoding and decoding of application layer PDUs.

use num_enum::TryFromPrimitive;

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

#[cfg(test)]
mod tests {
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

    // Test vectors derived from public Wireshark captures:
    // https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/mms.pcap.gz

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
                vendor_name: MMSString(VisibleString::from_iso646_bytes(b"Verrus Inc.").unwrap()),
                model_name: MMSString(VisibleString::from_iso646_bytes(b"Unit Test 9000").unwrap()),
                revision: MMSString(VisibleString::from_iso646_bytes(b"1.2.3").unwrap()),
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
                                    domain_id: Identifier(VisibleString::from_iso646_bytes(b"KIRKLAND").unwrap()),
                                    item_id: Identifier(
                                        VisibleString::from_iso646_bytes(b"Bilateral_Table_ID").unwrap(),
                                    ),
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
                    VisibleString::from_iso646_bytes(b"1.0").unwrap(),
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
                                    domain_id: Identifier(VisibleString::from_iso646_bytes(b"KIRKLAND").unwrap()),
                                    item_id: Identifier(VisibleString::from_iso646_bytes(b"CITEC_TS1").unwrap()),
                                },
                            )),
                            alternate_access: None,
                        },
                    ]),
                ),
                list_of_data: vec![Data::structure(vec![
                    Data::structure(vec![
                        Data::unsigned(Integer::Primitive(1)),
                        Data::visible_string(VisibleString::from_iso646_bytes(b"KIRKLAND").unwrap()),
                        Data::visible_string(VisibleString::from_iso646_bytes(b"EMS_STATUS_ICCP_IN").unwrap()),
                    ]),
                    Data::integer(Integer::Primitive(0)),
                    Data::integer(Integer::Primitive(0)),
                    Data::integer(Integer::Primitive(0)),
                    Data::integer(Integer::Primitive(1)),
                    Data::integer(Integer::Primitive(0)),
                    Data::bit_string(bitvec![u8, Msb0; 0, 0, 1, 0, 0]),
                    Data::boolean(false),
                    Data::boolean(false),
                    Data::boolean(true),
                    Data::boolean(true),
                    Data::integer(Integer::Primitive(0)),
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
                    VisibleString::from_iso646_bytes(b"KIRKLAND").unwrap(),
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
                    Identifier(VisibleString::from_iso646_bytes(b"EMS_ANALOG_ICCP_IN").unwrap()),
                    Identifier(VisibleString::from_iso646_bytes(b"EMS_STATUS_ICCP_IN").unwrap()),
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
