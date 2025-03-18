//! Minimal implemenation of ISO-8823 OSI presentation layer.
//! Code bindings were generated from `ISO-8823-PRESENTATION.asn`.
//! ITU-T X.226 is referenced in the below code.

use bytes::{Buf, Bytes, BytesMut};
use rasn::{ber, de::Decode, enc::Encode, types::*};

use crate::{
    error::Error,
    messages::{acse_1, iso_9506_mms_1, iso8823_presentation},
    oid,
};

// Version 1
const PROTOCOL_VERSION: u8 = 0b10000000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentationParams {
    /// Sender's presentation address
    pub local_presentation_selector: Option<OctetString>,
    /// Recipient's presentation address
    pub remote_presentation_selector: Option<OctetString>,
    /// Presentation context identifier for payloads with ACSE syntax (**must** be odd number)
    pub acse_context_id: Integer,
    /// Presentation context identifier for payloads with MMS syntax (**must** be odd number)
    pub mms_context_id: Integer,
}

impl Default for PresentationParams {
    fn default() -> Self {
        Self {
            local_presentation_selector: None,
            remote_presentation_selector: None,
            acse_context_id: Integer::Primitive(1),
            mms_context_id: Integer::Primitive(3),
        }
    }
}

pub struct Ppdu;

impl Ppdu {
    /// Serialize a CP-PPDU to an output buffer
    pub fn encode_connect(pp: &PresentationParams, apdu: &acse_1::ACSEApdu, dst: &mut BytesMut) -> Result<(), Error> {
        use iso8823_presentation::*;

        assert_ne!(pp.acse_context_id, pp.mms_context_id);

        let ppdu = CPPPDU {
            mode_selector: ModeSelector {
                mode_value: Integer::Primitive(1), // normal-mode(1)
            },
            x410_mode_parameters: None,
            normal_mode_parameters: Some(CPPPDUNormalModeParameters {
                protocol_version: Some(ProtocolVersion(BitString::from_element(PROTOCOL_VERSION))),
                calling_presentation_selector: pp
                    .local_presentation_selector
                    .as_ref()
                    .map(|s| CallingPresentationSelector(PresentationSelector(s.clone()))),
                called_presentation_selector: pp
                    .remote_presentation_selector
                    .as_ref()
                    .map(|s| CalledPresentationSelector(PresentationSelector(s.clone()))),
                presentation_context_definition_list: Some(PresentationContextDefinitionList(ContextList(vec![
                    AnonymousContextList {
                        presentation_context_identifier: PresentationContextIdentifier(pp.acse_context_id.clone()),
                        abstract_syntax_name: AbstractSyntaxName(acse_1::ACSE_AS_ID.clone()),
                        transfer_syntax_name_list: vec![TransferSyntaxName(oid::BASIC_ENCODING.clone())],
                    },
                    AnonymousContextList {
                        presentation_context_identifier: PresentationContextIdentifier(pp.mms_context_id.clone()),
                        abstract_syntax_name: AbstractSyntaxName(iso_9506_mms_1::MMS_ABSTRACT_SYNTAX_VERSION1.clone()),
                        transfer_syntax_name_list: vec![TransferSyntaxName(oid::BASIC_ENCODING.clone())],
                    },
                ]))),
                default_context_name: None,
                presentation_requirements: Some(PresentationRequirements(BitString::from_element(0x00))),
                user_session_requirements: None,
                protocol_options: None,
                initiators_nominated_context: None,
                extensions: None,
                user_data: Some(Ppdu::pack_user_data(&pp.acse_context_id, &apdu)?),
            }),
        };

        // Encode PPDU
        dst.extend_from_slice(&ber::encode(&ppdu)?);

        Ok(())
    }

    /// Deserialize a CP-PPDU from an input buffer
    pub fn decode_connect(src: &mut Bytes) -> Result<(PresentationParams, acse_1::ACSEApdu), Error> {
        use iso8823_presentation::*;

        let mut decoder = ber::de::Decoder::new(src, ber::de::DecoderOptions::ber());

        let ppdu = CPPPDU::decode(&mut decoder)?;
        src.advance(decoder.decoded_len());

        let params = ppdu.normal_mode_parameters.ok_or(Error::ProtocolError(
            "Presentation: no normal mode parameters in CP-PDU".into(),
        ))?;

        // Map ACSE and MMS presentation context IDs for use when encodng and decoding other packets
        let mut acse_context_id = None;
        let mut mms_context_id = None;
        let contexts = params.presentation_context_definition_list.ok_or(Error::ProtocolError(
            "Presentation: no context definition list in CP-PDU".into(),
        ))?;
        for context in contexts.0.0 {
            let id = context.presentation_context_identifier.0;
            let syntax = &context.abstract_syntax_name.0;

            if syntax == acse_1::ACSE_AS_ID.as_ref() {
                acse_context_id = Some(id);
            } else if syntax == iso_9506_mms_1::MMS_ABSTRACT_SYNTAX_VERSION1.as_ref() {
                mms_context_id = Some(id);
            }
        }

        let pp = PresentationParams {
            acse_context_id: acse_context_id.ok_or(Error::ProtocolError(format!(
                "Presentation: missing ACSE {:?} context definition in CP-PDU",
                acse_1::ACSE_AS_ID.as_ref()
            )))?,
            mms_context_id: mms_context_id.ok_or(Error::ProtocolError(format!(
                "Presentation: missing MMS {:?} context definition in CP-PDU",
                iso_9506_mms_1::MMS_ABSTRACT_SYNTAX_VERSION1.as_ref()
            )))?,
            // Note: "calling" and "called" intentionally swapped to reflect recipient's perspective
            local_presentation_selector: params.called_presentation_selector.map(|p| p.0.0),
            remote_presentation_selector: params.calling_presentation_selector.map(|p| p.0.0),
        };

        let user_data = params
            .user_data
            .ok_or(Error::ProtocolError("Presentation: no user data in CP-PDU".into()))?;

        let apdu = Ppdu::unpack_user_data(&pp.acse_context_id, &user_data)?;

        Ok((pp, apdu))
    }

    /// Serialize a CPA-PDU to an output buffer
    pub fn encode_connect_accept(
        pp: &PresentationParams,
        apdu: &acse_1::ACSEApdu,
        dst: &mut BytesMut,
    ) -> Result<(), Error> {
        use iso8823_presentation::*;

        let ppdu = CPAPPDU {
            mode_selector: ModeSelector {
                mode_value: Integer::Primitive(1), // normal-mode(1)
            },
            x410_mode_parameters: None,
            normal_mode_parameters: Some(CPAPPDUNormalModeParameters {
                protocol_version: Some(ProtocolVersion(BitString::from_element(PROTOCOL_VERSION))), // version-1(0)
                responding_presentation_selector: pp
                    .local_presentation_selector
                    .as_ref()
                    .map(|s| RespondingPresentationSelector(PresentationSelector(s.clone()))),
                presentation_context_definition_result_list: Some(PresentationContextDefinitionResultList(ResultList(
                    vec![
                        AnonymousResultList {
                            result: Result(Integer::Primitive(0)), // acceptance(0)
                            transfer_syntax_name: Some(TransferSyntaxName(oid::BASIC_ENCODING.clone())),
                            provider_reason: None,
                        },
                        AnonymousResultList {
                            result: Result(Integer::Primitive(0)), // acceptance(0)
                            transfer_syntax_name: Some(TransferSyntaxName(oid::BASIC_ENCODING.clone())),
                            provider_reason: None,
                        },
                    ],
                ))),
                presentation_requirements: None,
                user_session_requirements: None,
                protocol_options: None,
                responders_nominated_context: None,
                user_data: Some(Ppdu::pack_user_data(&pp.acse_context_id, &apdu)?),
            }),
        };

        // Encode PPDU
        dst.extend_from_slice(&ber::encode(&ppdu)?);

        Ok(())
    }

    /// Deserialize a CPA-PPDU from an input buffer
    pub fn decode_connect_accept(pp: &PresentationParams, src: &mut Bytes) -> Result<acse_1::ACSEApdu, Error> {
        use iso8823_presentation::*;

        let mut decoder = ber::de::Decoder::new(src, ber::de::DecoderOptions::ber());

        let ppdu = CPAPPDU::decode(&mut decoder)?;
        src.advance(decoder.decoded_len());

        let params = ppdu.normal_mode_parameters.ok_or(Error::ProtocolError(
            "Presentation: no normal mode parameters in CPA-PDU".into(),
        ))?;

        // Verify the remote presentation selector matches what was sent in the CP-PDU
        if let (Some(RespondingPresentationSelector(PresentationSelector(received))), Some(expected)) = (
            &params.responding_presentation_selector,
            &pp.remote_presentation_selector,
        ) {
            if received != expected {
                return Err(Error::ProtocolError(format!(
                    "Presentation: mismatched presentation selector in CPA-PDU: received {received:x}, expected {expected:x}"
                )));
            }
        }

        // Verify proposed ACSE and MMS presentation contexts were accepted
        let context_results = params
            .presentation_context_definition_result_list
            .ok_or(Error::ProtocolError(
                "Presentation: no context definition result list in CPA-PDU".into(),
            ))?;
        if context_results.0.0.len() != 2 {
            return Err(Error::ProtocolError(
                "Presentation: missing context results for ACSE and/or MMS CPA-PDU".into(),
            ));
        }
        if context_results.0.0.iter().any(
            |r| r.result != Result(Integer::Primitive(0)), // acceptance(0)
        ) {
            return Err(Error::ProtocolError(
                "Presentation: context not accepted for ACSE and/or MMS CPA-PDU".into(),
            ));
        }

        let user_data = params
            .user_data
            .ok_or(Error::ProtocolError("Presentation: no user data in CPA-PDU".into()))?;

        let apdu = Ppdu::unpack_user_data(&pp.acse_context_id, &user_data)?;

        Ok(apdu)
    }

    /// Serialize an ARU-PPDU to an output buffer
    #[allow(dead_code)]
    pub fn encode_abort_user(
        pp: &PresentationParams,
        apdu: &acse_1::ACSEApdu,
        dst: &mut BytesMut,
    ) -> Result<(), Error> {
        use iso8823_presentation::*;

        let ppdu = ARUPPDU::normal_mode_parameters(ARUPPDUNormalModeParameters {
            presentation_context_identifier_list: None,
            user_data: Some(Ppdu::pack_user_data(&pp.acse_context_id, &apdu)?),
        });

        // Encode PPDU
        dst.extend_from_slice(&ber::encode(&ppdu)?);

        Ok(())
    }

    /// Deserialize an ARU-PPDU from an input buffer
    pub fn decode_abort_user(pp: &PresentationParams, src: &mut Bytes) -> Result<acse_1::ACSEApdu, Error> {
        use iso8823_presentation::*;

        let mut decoder = ber::de::Decoder::new(src, ber::de::DecoderOptions::ber());

        let ppdu = ARUPPDU::decode(&mut decoder)?;
        src.advance(decoder.decoded_len());

        if let ARUPPDU::normal_mode_parameters(params) = ppdu {
            let user_data = params
                .user_data
                .ok_or(Error::ProtocolError("Presentation: no user data in ARU-PDU".into()))?;

            let apdu = Ppdu::unpack_user_data(&pp.acse_context_id, &user_data)?;

            Ok(apdu)
        } else {
            Err(Error::ProtocolError(
                "Presentation: no normal mode parameters in ARU-PDU".into(),
            ))
        }
    }

    /// Serialize an ACSE User-Data PPDU to an output buffer
    #[allow(dead_code)]
    pub fn encode_data_acse(pp: &PresentationParams, apdu: &acse_1::ACSEApdu, dst: &mut BytesMut) -> Result<(), Error> {
        let ppdu = Ppdu::pack_user_data(&pp.acse_context_id, &apdu)?;

        dst.extend_from_slice(&ber::encode(&ppdu)?);

        Ok(())
    }

    /// Deserialize an ACSE User-Data PPDU from an input buffer
    pub fn decode_data_acse(pp: &PresentationParams, src: &mut Bytes) -> Result<acse_1::ACSEApdu, Error> {
        use iso8823_presentation::*;

        let mut decoder = ber::de::Decoder::new(src, ber::de::DecoderOptions::ber());

        let ppdu = UserData::decode(&mut decoder)?;
        src.advance(decoder.decoded_len());

        let apdu = Ppdu::unpack_user_data(&pp.acse_context_id, &ppdu)?;

        Ok(apdu)
    }

    /// Serialize an MMS User-Data PPDU to an output buffer
    pub fn encode_data_mms(
        pp: &PresentationParams,
        mpdu: &iso_9506_mms_1::MMSpdu,
        dst: &mut BytesMut,
    ) -> Result<(), Error> {
        let ppdu = Ppdu::pack_user_data(&pp.mms_context_id, &mpdu)?;

        dst.extend_from_slice(&ber::encode(&ppdu)?);

        Ok(())
    }

    /// Deserialize an MMS User-Data PPDU from an input buffer
    pub fn decode_data_mms(pp: &PresentationParams, src: &mut Bytes) -> Result<iso_9506_mms_1::MMSpdu, Error> {
        use iso8823_presentation::*;

        let mut decoder = ber::de::Decoder::new(src, ber::de::DecoderOptions::ber());

        let ppdu = UserData::decode(&mut decoder)?;
        src.advance(decoder.decoded_len());

        let mpdu = Ppdu::unpack_user_data(&pp.mms_context_id, &ppdu)?;

        Ok(mpdu)
    }

    /// Create a `UserData` structure with an ASN.1 BER encoded payload
    fn pack_user_data<E: Encode>(context_id: &Integer, asn1: &E) -> Result<iso8823_presentation::UserData, Error> {
        use iso8823_presentation::*;

        let user_data = UserData::fully_encoded_data(FullyEncodedData(vec![PDVList {
            transfer_syntax_name: None,
            presentation_context_identifier: PresentationContextIdentifier(context_id.clone()),
            presentation_data_values: PDVListPresentationDataValues::single_ASN1_type(Any::new(ber::encode(&asn1)?)),
        }]));

        Ok(user_data)
    }

    /// Extract an ASN.1 BER encoded payload from a `UserData` structure
    fn unpack_user_data<D: Decode>(
        context_id: &Integer,
        user_data: &iso8823_presentation::UserData,
    ) -> Result<D, Error> {
        use iso8823_presentation::*;

        let asn1 = match user_data {
            UserData::fully_encoded_data(FullyEncodedData(pdv_list)) => {
                let pdv = pdv_list
                    .first()
                    .ok_or(Error::ProtocolError("Presentation: empty PDV list in PPDU".into()))?
                    .to_owned();

                if pdv.presentation_context_identifier.0 != *context_id {
                    return Err(Error::ProtocolError(format!(
                        "Presentation: user data context ID mismatch: expected {context_id}, received {}",
                        pdv.presentation_context_identifier.0
                    )));
                }

                match pdv.presentation_data_values {
                    PDVListPresentationDataValues::single_ASN1_type(asn1) => ber::decode(asn1.as_bytes())?,

                    _ => {
                        return Err(Error::ProtocolError(
                            "Presentation: expected single-ASN1-type user data".into(),
                        ));
                    }
                }
            }

            _ => {
                return Err(Error::ProtocolError(
                    "Presentation: expected Fully-encoded-data user data".into(),
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
    fn connect() {
        let expected = hex::decode("3181a3a003800101a2819b80020080810400000001820400000002a423300f0201010604520100013004060251013010020103060528ca220201300406025101880200006160305e020101a059605780020780a107060528ca220101a20406022902a303020102a60406022901a703020101be32283006025101020103a027a82580027d00810114820114830104a416800101810305fb00820c036e1d000000000064000198").unwrap();

        let params = PresentationParams {
            local_presentation_selector: Some(OctetString::from_static(&[0, 0, 0, 1])),
            remote_presentation_selector: Some(OctetString::from_static(&[0, 0, 0, 2])),
            acse_context_id: Integer::Primitive(1),
            mms_context_id: Integer::Primitive(3),
        };

        let user_data = hex::decode("605780020780a107060528ca220101a20406022902a303020102a60406022901a703020101be32283006025101020103a027a82580027d00810114820114830104a416800101810305fb00820c036e1d000000000064000198").unwrap();
        let apdu: acse_1::ACSEApdu = ber::decode(&user_data).unwrap();

        let mut buf = BytesMut::new();

        // Encode
        Ppdu::encode_connect(&params, &apdu, &mut buf).unwrap();
        assert_eq!(expected, buf.to_vec());

        let mut buf = buf.freeze();

        // Decode
        let (params2, apdu2) = Ppdu::decode_connect(&mut buf).unwrap();

        // "Calling" and "Called" params are swapped on decode to match the perspective of the recipient
        assert_eq!(params.local_presentation_selector, params2.remote_presentation_selector);
        assert_eq!(params.remote_presentation_selector, params2.local_presentation_selector);
        assert_eq!(params.acse_context_id, params2.acse_context_id);
        assert_eq!(params.mms_context_id, params2.mms_context_id);

        assert_eq!(apdu, apdu2);
    }

    #[test]
    fn connect_accept() {
        let expected = hex::decode("318184a003800101a27d80020080830400000002a512300780010081025101300780010081025101615d305b020101a056615480020780a107060528ca220101a203020100a305a103020100a40406022902a503020102be2e282c020103a027a92580027d00810114820114830104a416800101810305fb00820c036e1d000000000064000198").unwrap();

        let tx_params = PresentationParams {
            local_presentation_selector: Some(OctetString::from_static(&[0, 0, 0, 2])),
            remote_presentation_selector: Some(OctetString::from_static(&[0, 0, 0, 1])),
            acse_context_id: Integer::Primitive(1),
            mms_context_id: Integer::Primitive(3),
        };

        let user_data = hex::decode("615480020780a107060528ca220101a203020100a305a103020100a40406022902a503020102be2e282c020103a027a92580027d00810114820114830104a416800101810305fb00820c036e1d000000000064000198").unwrap();
        let apdu: acse_1::ACSEApdu = ber::decode(&user_data).unwrap();

        let mut buf = BytesMut::new();

        // Encode
        Ppdu::encode_connect_accept(&tx_params, &apdu, &mut buf).unwrap();
        assert_eq!(expected, buf.to_vec());

        let mut buf = buf.freeze();

        // Decode
        let rx_params = PresentationParams {
            local_presentation_selector: Some(OctetString::from_static(&[0, 0, 0, 1])),
            remote_presentation_selector: Some(OctetString::from_static(&[0, 0, 0, 2])),
            acse_context_id: Integer::Primitive(1),
            mms_context_id: Integer::Primitive(3),
        };
        let apdu2 = Ppdu::decode_connect_accept(&rx_params, &mut buf).unwrap();
        assert_eq!(apdu, apdu2);
    }

    #[test]
    fn abort_user() {
        let expected = hex::decode("a00e610c300a020101a0056403800100").unwrap();

        let params = PresentationParams {
            local_presentation_selector: Some(OctetString::from_static(&[0, 0, 0, 1])),
            remote_presentation_selector: Some(OctetString::from_static(&[0, 0, 0, 2])),
            acse_context_id: Integer::Primitive(1),
            mms_context_id: Integer::Primitive(3),
        };

        let user_data = hex::decode("6403800100").unwrap();
        let apdu: acse_1::ACSEApdu = ber::decode(&user_data).unwrap();

        let mut buf = BytesMut::new();

        // Encode
        Ppdu::encode_abort_user(&params, &apdu, &mut buf).unwrap();
        assert_eq!(expected, buf.to_vec());

        let mut buf = buf.freeze();

        // Decode
        let apdu2 = Ppdu::decode_abort_user(&params, &mut buf).unwrap();
        assert_eq!(apdu, apdu2);
    }

    #[test]
    fn data_acse() {
        let expected = hex::decode("610c300a020101a0056203800100").unwrap();

        let params = PresentationParams {
            local_presentation_selector: Some(OctetString::from_static(&[0, 0, 0, 1])),
            remote_presentation_selector: Some(OctetString::from_static(&[0, 0, 0, 2])),
            acse_context_id: Integer::Primitive(1),
            mms_context_id: Integer::Primitive(3),
        };

        let user_data = hex::decode("6203800100").unwrap();
        let apdu: acse_1::ACSEApdu = ber::decode(&user_data).unwrap();

        let mut buf = BytesMut::new();

        // Encode
        Ppdu::encode_data_acse(&params, &apdu, &mut buf).unwrap();
        assert_eq!(expected, buf.to_vec());

        let mut buf = buf.freeze();

        // Decode
        let apdu2 = Ppdu::decode_data_acse(&params, &mut buf).unwrap();
        assert_eq!(apdu, apdu2);
    }

    #[test]
    fn data_mms() {
        let expected = hex::decode("610f300d020103a008a0060202114f8200").unwrap();

        let params = PresentationParams {
            local_presentation_selector: Some(OctetString::from_static(&[0, 0, 0, 1])),
            remote_presentation_selector: Some(OctetString::from_static(&[0, 0, 0, 2])),
            acse_context_id: Integer::Primitive(1),
            mms_context_id: Integer::Primitive(3),
        };

        let user_data = hex::decode("a0060202114f8200").unwrap();
        let mpdu: iso_9506_mms_1::MMSpdu = ber::decode(&user_data).unwrap();

        let mut buf = BytesMut::new();

        // Encode
        Ppdu::encode_data_mms(&params, &mpdu, &mut buf).unwrap();
        assert_eq!(expected, buf.to_vec());

        let mut buf = buf.freeze();

        // Decode
        let mpdu2 = Ppdu::decode_data_mms(&params, &mut buf).unwrap();
        assert_eq!(mpdu, mpdu2);
    }
}
