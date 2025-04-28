//! Minimal implemenation of ISO-8650 OSI Association Control layer.
//! Code bindings were generated from `ISO-8650-ACSE-1.asn`.
//! ITU-T X.227 is referenced in the below code.

use num_enum::TryFromPrimitive;
use rasn::{ber, de::Decode, enc::Encode, types::*};

use crate::{
    error::Error,
    messages::{acse_1, iso_9506_mms_1},
    oid,
};

// Version 1
const PROTOCOL_VERSION: u8 = 0b10000000;

/// Who initiated the abort [X.227 Section 7.3.4.1]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum AbortSource {
    User = 0,
    Provider = 1,
}

pub struct Apdu;

impl Apdu {
    /// Create an ACSE AARQ-APDU with an MMS payload
    pub fn pack_associate_request(
        presentation_context_id: &Integer,
        mpdu: &iso_9506_mms_1::MMSpdu,
    ) -> Result<acse_1::ACSEApdu, Error> {
        use acse_1::*;

        let apdu = ACSEApdu::aarq(AARQApdu {
            protocol_version: Some(BitString::from_element(PROTOCOL_VERSION)),
            a_so_context_name: ASOContextName(oid::MMS_APPLICATION_CONTEXT.clone()),
            called_ap_title: Some(APTitle::ap_title_form2(APTitleForm2(
                oid::ISO_REGISTRATION_AUTHORITY_2.clone(),
            ))),
            called_ae_qualifier: Some(AEQualifier(ASOQualifier::aso_qualifier_form2(ASOQualifierForm2(
                Integer::from(2),
            )))),
            called_ap_invocation_identifier: None,
            called_ae_invocation_identifier: None,
            calling_ap_title: Some(APTitle::ap_title_form2(APTitleForm2(
                oid::ISO_REGISTRATION_AUTHORITY_1.clone(),
            ))),
            calling_ae_qualifier: Some(AEQualifier(ASOQualifier::aso_qualifier_form2(ASOQualifierForm2(
                Integer::from(1),
            )))),
            calling_ap_invocation_identifier: None,
            calling_ae_invocation_identifier: None,
            sender_acse_requirements: None,
            mechanism_name: None,
            calling_authentication_value: None,
            a_so_context_name_list: None,
            implementation_information: None,
            p_context_definition_list: None,
            called_asoi_tag: None,
            calling_asoi_tag: None,
            user_information: Some(Apdu::pack_association_data(presentation_context_id, &mpdu)?),
        });

        Ok(apdu)
    }

    /// Extract an MMS payload from an ACSE AARQ-APDU
    pub fn unpack_associate_request(
        presentation_context_id: &Integer,
        apdu: &acse_1::ACSEApdu,
    ) -> Result<iso_9506_mms_1::MMSpdu, Error> {
        use acse_1::*;

        let mpdu = match apdu {
            ACSEApdu::aarq(aarq) => {
                if aarq.a_so_context_name.0.as_ref() != oid::MMS_APPLICATION_CONTEXT.as_ref() {
                    return Err(Error::ProtocolError(format!(
                        "ACSE: expected MMS {:?} ASO context",
                        oid::MMS_APPLICATION_CONTEXT.as_ref()
                    )));
                }

                let association_data = aarq.user_information.as_ref().ok_or(Error::ProtocolError(
                    "ACSE: expected user information in AARQ-APDU".into(),
                ))?;

                Apdu::unpack_association_data(presentation_context_id, association_data)?
            }

            _ => {
                return Err(Error::ProtocolError(
                    "ACSE: expected an AARQ-APDU in associatiation request".into(),
                ));
            }
        };

        Ok(mpdu)
    }

    /// Create an ACSE AARE-APDU with an MMS payload
    pub fn pack_associate_response(
        presentation_context_id: &Integer,
        mpdu: &iso_9506_mms_1::MMSpdu,
    ) -> Result<acse_1::ACSEApdu, Error> {
        use acse_1::*;

        let apdu = ACSEApdu::aare(AAREApdu {
            protocol_version: Some(BitString::from_element(0b10000000)), // version1(0)
            a_so_context_name: ASOContextName(oid::MMS_APPLICATION_CONTEXT.clone()),
            result: acse_1::AssociateResult(0), // accepted(0)
            result_source_diagnostic: acse_1::AssociateSourceDiagnostic::acse_service_user(0), // null(0)
            responding_ap_title: Some(APTitle::ap_title_form2(APTitleForm2(
                oid::ISO_REGISTRATION_AUTHORITY_2.clone(),
            ))),
            responding_ae_qualifier: Some(AEQualifier(ASOQualifier::aso_qualifier_form2(ASOQualifierForm2(
                Integer::from(2),
            )))),
            responding_ap_invocation_identifier: None,
            responding_ae_invocation_identifier: None,
            responder_acse_requirements: None,
            mechanism_name: None,
            responding_authentication_value: None,
            a_so_context_name_list: None,
            implementation_information: None,
            p_context_result_list: None,
            called_asoi_tag: None,
            calling_asoi_tag: None,
            user_information: Some(Apdu::pack_association_data(presentation_context_id, &mpdu)?),
        });

        Ok(apdu)
    }

    /// Extract an MMS payload from an ACSE AARE-APDU
    pub fn unpack_associate_response(
        presentation_context_id: &Integer,
        apdu: &acse_1::ACSEApdu,
    ) -> Result<iso_9506_mms_1::MMSpdu, Error> {
        use acse_1::*;

        let mpdu = match apdu {
            ACSEApdu::aare(aare) => {
                if aare.a_so_context_name.0.as_ref() != oid::MMS_APPLICATION_CONTEXT.as_ref() {
                    // XXX Skip ASO context check as servers have been observed to vary in their responses.
                    // Assume if BER decoding is successful, the payload is compatible.

                    // return Err(Error::ProtocolError(format!(
                    //     "ACSE: expected MMS {:?} ASO context",
                    //     oid::MMS_APPLICATION_CONTEXT.as_ref()
                    // )));
                }

                // accepted(0)
                if aare.result.0 != 0 {
                    return Err(Error::ProtocolError("ACSE: MMS association rejected".into()));
                }

                let association_data = aare.user_information.as_ref().ok_or(Error::ProtocolError(
                    "ACSE: expected user information in AARQ-APDU".into(),
                ))?;

                Apdu::unpack_association_data(presentation_context_id, association_data)?
            }

            _ => {
                return Err(Error::ProtocolError(
                    "ACSE: expected an AARE-APDU in associatiation response".into(),
                ));
            }
        };

        Ok(mpdu)
    }

    /// Create an ACSE RLRQ-APDU for normal release
    #[allow(dead_code)] // Not used yet
    pub fn pack_release_request() -> Result<acse_1::ACSEApdu, Error> {
        use acse_1::*;

        let apdu = ACSEApdu::rlrq(RLRQApdu {
            reason: Some(ReleaseRequestReason(Integer::from(0))), // normal(0)
            aso_qualifier: None,
            asoi_identifier: None,
            user_information: None,
        });

        Ok(apdu)
    }

    /// Validate an RLRQ-APDU
    pub fn unpack_release_request(apdu: &acse_1::ACSEApdu) -> Result<(), Error> {
        use acse_1::*;

        if !matches!(apdu, ACSEApdu::rlrq(_)) {
            return Err(Error::ProtocolError(
                "ACSE: expected an RLRQ-APDU in release request".into(),
            ));
        }

        Ok(())
    }

    /// Create an ACSE RLRE-APDU for normal release
    #[allow(dead_code)] // Not used yet
    pub fn pack_release_response() -> Result<acse_1::ACSEApdu, Error> {
        use acse_1::*;

        let apdu = ACSEApdu::rlre(RLREApdu {
            reason: Some(ReleaseResponseReason(Integer::from(0))), // normal(0)
            aso_qualifier: None,
            asoi_identifier: None,
            user_information: None,
        });

        Ok(apdu)
    }

    /// Validate an RLRE-APDU
    pub fn unpack_release_response(apdu: &acse_1::ACSEApdu) -> Result<(), Error> {
        use acse_1::*;

        if !matches!(apdu, ACSEApdu::rlre(_)) {
            return Err(Error::ProtocolError(
                "ACSE: expected an RLRE-APDU in release response".into(),
            ));
        }

        Ok(())
    }

    /// Create an ACSE ABRT-APDU for normal release
    #[allow(dead_code)] // Not used yet
    pub fn pack_abort(source: AbortSource) -> Result<acse_1::ACSEApdu, Error> {
        use acse_1::*;

        let apdu = ACSEApdu::abrt(ABRTApdu {
            abort_source: ABRTSource(source as u8),
            abort_diagnostic: None,
            aso_qualifier: None,
            asoi_identifier: None,
            user_information: None,
        });

        Ok(apdu)
    }

    /// Unpack an ABRT-APDU
    pub fn unpack_abort(apdu: &acse_1::ACSEApdu) -> Result<AbortSource, Error> {
        use acse_1::*;

        let source = match apdu {
            ACSEApdu::abrt(abrt) => AbortSource::try_from(abrt.abort_source.0)
                .map_err(|e| Error::ProtocolError(format!("ACSE: invalid Abort-source: {e}")))?,

            _ => {
                return Err(Error::ProtocolError(
                    "ACSE: expected an ABRT-APDU in abort message".into(),
                ));
            }
        };

        Ok(source)
    }

    /// Create a `AssociationData` structure with an ASN.1 BER encoded payload
    fn pack_association_data<E: Encode>(
        presentation_context_id: &Integer,
        asn1: &E,
    ) -> Result<acse_1::AssociationData, Error> {
        use acse_1::*;

        let association_data = AssociationData(vec![ExternalData {
            direct_reference: Some(oid::BASIC_ENCODING.clone()),
            indirect_reference: Some(presentation_context_id.clone()),
            encoding: ExternalDataEncoding::single_ASN1_type(Any::new(ber::encode(&asn1)?)),
        }]);

        Ok(association_data)
    }

    /// Extract an ASN.1 BER encoded payload from a `UserData` structure
    fn unpack_association_data<D: Decode>(
        presentation_context_id: &Integer,
        association_data: &acse_1::AssociationData,
    ) -> Result<D, Error> {
        use acse_1::*;

        let data = association_data
            .0
            .first()
            .ok_or(Error::ProtocolError("ACSE: empty association data in APDU".into()))?
            .to_owned();

        let indirect_reference = data.indirect_reference.ok_or(Error::ProtocolError(
            "ACSE: expected indirect reference to association data".into(),
        ))?;

        if indirect_reference != *presentation_context_id {
            return Err(Error::ProtocolError(format!(
                "ACSE: association data context ID mismatch: expected {presentation_context_id}, received {indirect_reference}"
            )));
        }

        let asn1 = match data.encoding {
            ExternalDataEncoding::single_ASN1_type(asn1) => ber::decode(asn1.as_bytes())?,

            _ => {
                return Err(Error::ProtocolError(
                    "ACSE: expected single-ASN1-type association encoding".into(),
                ));
            }
        };

        Ok(asn1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors derived from public Wireshark captures:
    // https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/mms.pcap.gz

    #[test]
    fn associate_request() {
        let expected = hex::decode("605780020080a107060528ca220205a20406022902a303020102a60406022901a703020101be32283006025101020103a027a82580027d00810114820114830104a416800101810305fb00820c036e1d000000000064000198").unwrap();

        let user_data =
            hex::decode("a82580027d00810114820114830104a416800101810305fb00820c036e1d000000000064000198").unwrap();
        let mpdu: iso_9506_mms_1::MMSpdu = ber::decode(&user_data).unwrap();

        // Pack
        let apdu = Apdu::pack_associate_request(&Integer::from(3), &mpdu).unwrap();
        assert_eq!(expected, ber::encode(&apdu).unwrap());

        // Unpack
        let mpdu2 = Apdu::unpack_associate_request(&Integer::from(3), &apdu).unwrap();
        assert_eq!(mpdu, mpdu2);
    }

    #[test]
    fn associate_response() {
        let expected = hex::decode("615880020080a107060528ca220205a203020100a305a103020100a40406022902a503020102be32283006025101020103a027a92580027d00810114820114830104a416800101810305fb00820c036e1d000000000064000198").unwrap();

        let user_data =
            hex::decode("a92580027d00810114820114830104a416800101810305fb00820c036e1d000000000064000198").unwrap();
        let mpdu: iso_9506_mms_1::MMSpdu = ber::decode(&user_data).unwrap();

        // Pack
        let apdu = Apdu::pack_associate_response(&Integer::from(3), &mpdu).unwrap();
        assert_eq!(expected, ber::encode(&apdu).unwrap());

        // Unpack
        let mpdu2 = Apdu::unpack_associate_response(&Integer::from(3), &apdu).unwrap();
        assert_eq!(mpdu, mpdu2);
    }

    #[test]
    fn release_request() {
        let expected = hex::decode("6203800100").unwrap();

        // Pack
        let apdu = Apdu::pack_release_request().unwrap();
        assert_eq!(expected, ber::encode(&apdu).unwrap());

        // Unpack
        Apdu::unpack_release_request(&apdu).unwrap();
    }

    #[test]
    fn release_response() {
        let expected = hex::decode("6303800100").unwrap();

        // Pack
        let apdu = Apdu::pack_release_response().unwrap();
        assert_eq!(expected, ber::encode(&apdu).unwrap());

        // Unpack
        Apdu::unpack_release_response(&apdu).unwrap();
    }

    #[test]
    fn abort() {
        let expected = hex::decode("6403800100").unwrap();

        // Pack
        let apdu = Apdu::pack_abort(AbortSource::User).unwrap();
        assert_eq!(expected, ber::encode(&apdu).unwrap());

        // Unpack
        let source = Apdu::unpack_abort(&apdu).unwrap();
        assert_eq!(source, AbortSource::User);
    }
}
