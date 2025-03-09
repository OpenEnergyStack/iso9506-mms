//! Minimal implemenation of ISO-8327 OSI session layer.
//! ITU-T X.225 is referenced in the below code.

use crate::error::Error;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

/// SPDU identifiers (SI) [X.225 Section 8.3]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum SpduId {
    DataTransfer = 1, // Also GiveTokens
    Prepare = 7,
    Finish = 9,
    Disconnect = 10,
    Refuse = 12,
    Connect = 13,
    Accept = 14,
    ConnectDataOverflow = 15,
    OverflowAccept = 16,
    Abort = 25,
    AbortAccept = 26,
}

/// SPDU parameter group and parameter identifiers (PGI & PI) [X.225 Section 8.3]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum ParamId {
    ConnectionId = 1,
    ConnectAcceptItem = 5,
    CalledSSUserReference = 9,
    CallingSSUserReference = 10,
    CommonReference = 11,
    AdditionalReferenceInfo = 12,
    TokenItem = 16,
    TransportDisconnect = 17,
    ProtocolOptions = 19,
    SessionUserRequirements = 20,
    TSDUMaxSize = 21,
    VersionNumber = 22,
    InitialSerialNumber = 23,
    EnclosureItem = 25,
    TokenSettingItem = 26,
    ResyncType = 27,
    LinkingInformation = 33,
    ActivityIdentifier = 41,
    SerialNumber = 42,
    ReflectParameterValues = 49,
    ReasonCode = 50,
    CallingSessionSelector = 51,
    CalledSessionSelector = 52,
    SecondResyncType = 53,
    SecondSerialNumber = 54,
    SecondInitialSerialNumber = 55,
    UpperLimitSerialNumber = 56,
    LargeInitialSerialNumber = 57,
    LargeSecondInitialSerialNumber = 58,
    DataOverflow = 60,
    UserData = 193,
    ExtendedUserData = 194,
}

/// Connect (CN) SPDU parameters [X.225 Section 8.3.1]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectParams {
    pub calling_session_selector: Option<Bytes>,
    pub called_session_selector: Option<Bytes>,
    pub user_data: Option<Bytes>,
}

impl ConnectParams {
    fn encode(params: &ConnectParams, buf: &mut impl BufMut) {
        // Session User Requirements
        buf.put_u8(ParamId::SessionUserRequirements as u8);
        Spdu::encode_len(buf, 2);
        buf.put_u16(0x0002); // Disable all but Duplex functional unit [X.225 Section 8.3.1.16]

        // Calling Session Selector
        if let Some(id) = params.calling_session_selector.as_ref() {
            buf.put_u8(ParamId::CallingSessionSelector as u8);
            Spdu::encode_len(buf, id.len());
            buf.put_slice(id);
        }

        // Called Session Selector
        if let Some(id) = params.called_session_selector.as_ref() {
            buf.put_u8(ParamId::CalledSessionSelector as u8);
            Spdu::encode_len(buf, id.len());
            buf.put_slice(id);
        }

        // User Data
        if let Some(val) = params.user_data.as_ref() {
            buf.put_u8(ParamId::UserData as u8);
            Spdu::encode_len(buf, val.len());
            buf.put_slice(val);
        }
    }

    fn decode(buf: &mut impl Buf) -> Result<ConnectParams, Error> {
        let mut params = ConnectParams {
            calling_session_selector: None,
            called_session_selector: None,
            user_data: None,
        };

        // Decode and verify parameter groups and parameters. See[X.225 Table 11]
        while buf.has_remaining() {
            match Spdu::decode_param(buf)? {
                // Connection Identifier parameter group
                (ParamId::ConnectionId, mut buf) => {
                    while buf.has_remaining() {
                        match Spdu::decode_param(&mut buf)? {
                            (ParamId::CallingSSUserReference, _) => { /* Ok; not parsed */ }
                            (ParamId::CommonReference, _) => { /* Ok; not parsed */ }
                            (ParamId::AdditionalReferenceInfo, _) => { /* Ok; not parsed */ }
                            (param, _) => {
                                return Err(Error::ProtocolError(format!(
                                    "Session: unexpected Connect param: {:?}::{:?}",
                                    ParamId::ConnectionId,
                                    param
                                )));
                            }
                        }
                    }
                }

                // Connect/Accept Item parameter group
                (ParamId::ConnectAcceptItem, mut buf) => {
                    while buf.has_remaining() {
                        match Spdu::decode_param(&mut buf)? {
                            (ParamId::ProtocolOptions, _) => { /* Ok; not parsed */ }
                            (ParamId::TSDUMaxSize, _) => { /* Ok; not parsed */ }
                            (ParamId::VersionNumber, _) => { /* Ok; not parsed */ }
                            (ParamId::InitialSerialNumber, _) => { /* Ok; not parsed */ }
                            (ParamId::TokenSettingItem, _) => { /* Ok; not parsed */ }
                            (ParamId::SecondInitialSerialNumber, _) => { /* Ok; not parsed */ }
                            (ParamId::UpperLimitSerialNumber, _) => { /* Ok; not parsed */ }
                            (ParamId::LargeInitialSerialNumber, _) => { /* Ok; not parsed */ }
                            (ParamId::LargeSecondInitialSerialNumber, _) => { /* Ok; not parsed */ }
                            (param, _) => {
                                return Err(Error::ProtocolError(format!(
                                    "Session: unexpected Connect param: {:?}::{:?}",
                                    ParamId::ConnectAcceptItem,
                                    param
                                )));
                            }
                        }
                    }
                }

                // Non-group parameters
                (ParamId::SessionUserRequirements, _) => { /* Ok; not parsed */ }
                (ParamId::CalledSessionSelector, val) => {
                    params.called_session_selector = Some(val);
                }
                (ParamId::CallingSessionSelector, val) => {
                    params.calling_session_selector = Some(val);
                }
                (ParamId::DataOverflow, _) => { /* Ok; not parsed */ }
                (ParamId::UserData, val) => {
                    params.user_data = Some(val);
                }
                (param, _) => {
                    return Err(Error::ProtocolError(format!(
                        "Session: unexpected Connect param: {param:?}"
                    )));
                }
            }
        }

        Ok(params)
    }
}

/// Accept (AC) SPDU parameters [X.225 Section 8.3.4]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptParams {
    pub calling_session_selector: Option<Bytes>,
    pub responding_session_selector: Option<Bytes>,
    pub user_data: Option<Bytes>,
}

impl AcceptParams {
    fn encode(params: &AcceptParams, buf: &mut impl BufMut) {
        // Session User Requirements
        buf.put_u8(ParamId::SessionUserRequirements as u8);
        Spdu::encode_len(buf, 2);
        buf.put_u16(0x0002); // Disable all but Duplex functional unit [X.225 Section 8.3.1.16]

        // Calling Session Selector
        if let Some(id) = params.calling_session_selector.as_ref() {
            buf.put_u8(ParamId::CallingSessionSelector as u8);
            Spdu::encode_len(buf, id.len());
            buf.put_slice(id);
        }

        // Called Session Selector
        if let Some(id) = params.responding_session_selector.as_ref() {
            buf.put_u8(ParamId::CalledSessionSelector as u8);
            Spdu::encode_len(buf, id.len());
            buf.put_slice(id);
        }

        // User Data
        if let Some(val) = params.user_data.as_ref() {
            buf.put_u8(ParamId::UserData as u8);
            Spdu::encode_len(buf, val.len());
            buf.put_slice(val);
        }
    }

    fn decode(buf: &mut impl Buf) -> Result<AcceptParams, Error> {
        let mut params = AcceptParams {
            calling_session_selector: None,
            responding_session_selector: None,
            user_data: None,
        };

        // Decode and verify parameter groups and parameters. See[X.225 Table 14]
        while buf.has_remaining() {
            match Spdu::decode_param(buf)? {
                // Connection Identifier parameter group
                (ParamId::ConnectionId, mut buf) => {
                    while buf.has_remaining() {
                        match Spdu::decode_param(&mut buf)? {
                            (ParamId::CalledSSUserReference, _) => { /* Ok; not parsed */ }
                            (ParamId::CommonReference, _) => { /* Ok; not parsed */ }
                            (ParamId::AdditionalReferenceInfo, _) => { /* Ok; not parsed */ }
                            (param, _) => {
                                return Err(Error::ProtocolError(format!(
                                    "Session: unexpected Accept param: {:?}::{:?}",
                                    ParamId::ConnectionId,
                                    param
                                )));
                            }
                        }
                    }
                }

                // Connect/Accept Item parameter group
                (ParamId::ConnectAcceptItem, mut buf) => {
                    while buf.has_remaining() {
                        match Spdu::decode_param(&mut buf)? {
                            (ParamId::ProtocolOptions, _) => { /* Ok; not parsed */ }
                            (ParamId::TSDUMaxSize, _) => { /* Ok; not parsed */ }
                            (ParamId::VersionNumber, _) => { /* Ok; not parsed */ }
                            (ParamId::InitialSerialNumber, _) => { /* Ok; not parsed */ }
                            (ParamId::TokenSettingItem, _) => { /* Ok; not parsed */ }
                            (ParamId::SecondInitialSerialNumber, _) => { /* Ok; not parsed */ }
                            (ParamId::UpperLimitSerialNumber, _) => { /* Ok; not parsed */ }
                            (ParamId::LargeInitialSerialNumber, _) => { /* Ok; not parsed */ }
                            (ParamId::LargeSecondInitialSerialNumber, _) => { /* Ok; not parsed */ }
                            (param, _) => {
                                return Err(Error::ProtocolError(format!(
                                    "Session: unexpected Accept param: {:?}::{:?}",
                                    ParamId::ConnectAcceptItem,
                                    param
                                )));
                            }
                        }
                    }
                }

                // Non-group parameters
                (ParamId::TokenItem, _) => { /* Ok; not parsed */ }
                (ParamId::SessionUserRequirements, _) => { /* Ok; not parsed */ }
                (ParamId::EnclosureItem, _) => { /* Ok; not parsed */ }
                (ParamId::CallingSessionSelector, val) => {
                    params.calling_session_selector = Some(val);
                }
                (ParamId::CalledSessionSelector, val) => {
                    params.responding_session_selector = Some(val);
                }
                (ParamId::UserData, val) => {
                    params.user_data = Some(val);
                }
                (param, _) => {
                    return Err(Error::ProtocolError(format!(
                        "Session: unexpected Accept param: {param:?}"
                    )));
                }
            }
        }

        Ok(params)
    }
}

/// Finish (FN) SPDU parameters [X.225 Section 8.3.6]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinishParams {
    pub user_data: Option<Bytes>,
}

impl FinishParams {
    fn encode(params: &FinishParams, buf: &mut impl BufMut) {
        // User Data
        if let Some(val) = params.user_data.as_ref() {
            buf.put_u8(ParamId::UserData as u8);
            Spdu::encode_len(buf, val.len());
            buf.put_slice(val);
        }
    }

    fn decode(buf: &mut impl Buf) -> Result<FinishParams, Error> {
        let mut params = FinishParams { user_data: None };

        // Decode and verify parameters. See[X.225 Table 16]
        while buf.has_remaining() {
            match Spdu::decode_param(buf)? {
                // Non-group parameters
                (ParamId::TransportDisconnect, _) => { /* Ok; not parsed */ }
                (ParamId::EnclosureItem, _) => { /* Ok; not parsed */ }
                (ParamId::UserData, val) => {
                    params.user_data = Some(val);
                }
                (param, _) => {
                    return Err(Error::ProtocolError(format!(
                        "Session: unexpected Finish param: {param:?}"
                    )));
                }
            }
        }

        Ok(params)
    }
}

/// Disconnect (DN) SPDU parameters [X.225 Section 8.3.7]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisconnectParams {
    pub user_data: Option<Bytes>,
}

impl DisconnectParams {
    fn encode(params: &DisconnectParams, buf: &mut impl BufMut) {
        // User Data
        if let Some(val) = params.user_data.as_ref() {
            buf.put_u8(ParamId::UserData as u8);
            Spdu::encode_len(buf, val.len());
            buf.put_slice(val);
        }
    }

    fn decode(buf: &mut impl Buf) -> Result<DisconnectParams, Error> {
        let mut params = DisconnectParams { user_data: None };

        // Decode and verify parameters. See[X.225 Table 17]
        while buf.has_remaining() {
            match Spdu::decode_param(buf)? {
                // Non-group parameters
                (ParamId::EnclosureItem, _) => { /* Ok; not parsed */ }
                (ParamId::UserData, val) => {
                    params.user_data = Some(val);
                }
                (param, _) => {
                    return Err(Error::ProtocolError(format!(
                        "Session: unexpected Disconnect param: {param:?}"
                    )));
                }
            }
        }

        Ok(params)
    }
}

/// Abort (AB) SPDU parameters [X.225 Section 8.3.9]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbortParams {
    pub user_data: Option<Bytes>,
}

impl AbortParams {
    fn encode(params: &AbortParams, buf: &mut impl BufMut) {
        // Transport Disconnect
        buf.put_u8(ParamId::TransportDisconnect as u8);
        Spdu::encode_len(buf, 1);
        // transport-connection-release (1) | user-abort (2) | no-reason (4) [X.225 Section 8.3.9.3]
        buf.put_u8(0b00001011);

        // User Data
        if let Some(val) = params.user_data.as_ref() {
            buf.put_u8(ParamId::UserData as u8);
            Spdu::encode_len(buf, val.len());
            buf.put_slice(val);
        }
    }

    fn decode(buf: &mut impl Buf) -> Result<AbortParams, Error> {
        let mut params = AbortParams { user_data: None };

        // Decode and verify parameters. See[X.225 Table 19]
        while buf.has_remaining() {
            match Spdu::decode_param(buf)? {
                // Non-group parameters
                (ParamId::TransportDisconnect, _) => { /* Ok; not parsed */ }
                (ParamId::EnclosureItem, _) => { /* Ok; not parsed */ }
                (ParamId::ReflectParameterValues, _) => { /* Ok; not parsed */ }
                (ParamId::UserData, val) => {
                    params.user_data = Some(val);
                }
                (param, _) => {
                    return Err(Error::ProtocolError(format!(
                        "Session: unexpected Abort param: {param:?}"
                    )));
                }
            }
        }

        Ok(params)
    }
}

/// Data Transfer (DT) SPDU parameters [X.225 Section 8.3.11]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataTransferParams;

impl DataTransferParams {
    fn decode(buf: &mut impl Buf) -> Result<DataTransferParams, Error> {
        let params = DataTransferParams {};

        // Decode and verify parameter groups and parameters. See[X.225 Table 19]
        while buf.has_remaining() {
            match Spdu::decode_param(buf)? {
                // Non-group parameters
                (ParamId::EnclosureItem, _) => { /* Ok; not parsed */ }
                (param, _) => {
                    return Err(Error::ProtocolError(format!(
                        "Session: unexpected DataTransfer param: {param:?}"
                    )));
                }
            }
        }

        Ok(params)
    }
}

/// Give Tokens (GT) SPDU parameters [X.225 Section 8.3.16]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GiveTokensParams;

impl GiveTokensParams {
    fn decode(buf: &mut impl Buf) -> Result<GiveTokensParams, Error> {
        let params = GiveTokensParams {};

        // Decode and verify parameter groups and parameters. See[X.225 Table 25]
        while buf.has_remaining() {
            match Spdu::decode_param(buf)? {
                // Non-group parameters
                (ParamId::TokenItem, _) => { /* Ok; not parsed */ }
                (ParamId::EnclosureItem, _) => { /* Ok; not parsed */ }
                (param, _) => {
                    return Err(Error::ProtocolError(format!(
                        "Session: unexpected GiveTokens param: {param:?}"
                    )));
                }
            }
        }

        Ok(params)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Spdu {
    Connect(ConnectParams),
    Accept(AcceptParams),
    Finish(FinishParams),
    Disconnect(DisconnectParams),
    Abort(AbortParams),
    DataTransfer(DataTransferParams),
    GiveTokens(GiveTokensParams),
}

impl Spdu {
    const SI_SIZE: usize = 1; // Fixed
    const LI_SIZE: usize = 3; // Variable: 1-3 bytes

    // Serialize variable size length indicator field [X.225 Section 8.2.5]
    fn encode_len(buf: &mut impl BufMut, len: usize) {
        if len < 0xff {
            buf.put_u8(len as u8);
        } else if len < 0xffff {
            buf.put_u8(0xff);
            buf.put_u16(len as u16);
        } else {
            panic!("length field overflow");
        }
    }

    // Deserialize variable size length indicator field [X.225 Section 8.2.5]
    fn decode_len(buf: &mut impl Buf) -> Result<usize, Error> {
        let mut len = buf.try_get_u8()? as u16;

        if len == 0xff {
            len = buf.try_get_u16()?;
        }

        Ok(len as usize)
    }

    fn decode_param(buf: &mut impl Buf) -> Result<(ParamId, Bytes), Error> {
        let param = ParamId::try_from(buf.try_get_u8()?).map_err(proto_err)?;
        let len = Spdu::decode_len(buf)?;

        if buf.remaining() < len {
            return Err(Error::ProtocolError(format!(
                "Session: incomplete {param:?} param value: expected {len}B, available {}B",
                buf.remaining()
            )));
        }

        Ok((param, buf.copy_to_bytes(len)))
    }

    /// Serialize SPDU to output buffer
    pub fn encode(spdu: &Spdu, dst: &mut BytesMut) -> Result<(), Error> {
        match spdu {
            Spdu::Connect(params) => {
                let mut param_buf = BytesMut::new();
                ConnectParams::encode(params, &mut param_buf);

                dst.reserve(Spdu::SI_SIZE + Spdu::LI_SIZE + param_buf.len());

                dst.put_u8(SpduId::Connect as u8);
                Spdu::encode_len(dst, param_buf.len());
                dst.put(param_buf);
            }

            Spdu::Accept(params) => {
                let mut param_buf = BytesMut::new();
                AcceptParams::encode(params, &mut param_buf);

                dst.reserve(Spdu::SI_SIZE + Spdu::LI_SIZE + param_buf.len());

                dst.put_u8(SpduId::Accept as u8);
                Spdu::encode_len(dst, param_buf.len());
                dst.put(param_buf);
            }

            Spdu::Disconnect(params) => {
                let mut param_buf = BytesMut::new();
                DisconnectParams::encode(params, &mut param_buf);

                dst.reserve(Spdu::SI_SIZE + Spdu::LI_SIZE + param_buf.len());

                dst.put_u8(SpduId::Disconnect as u8);
                Spdu::encode_len(dst, param_buf.len());
                dst.put(param_buf);
            }

            Spdu::Finish(params) => {
                let mut param_buf = BytesMut::new();
                FinishParams::encode(params, &mut param_buf);

                dst.reserve(Spdu::SI_SIZE + Spdu::LI_SIZE + param_buf.len());

                dst.put_u8(SpduId::Finish as u8);
                Spdu::encode_len(dst, param_buf.len());
                dst.put(param_buf);
            }

            Spdu::Abort(params) => {
                let mut param_buf = BytesMut::new();
                AbortParams::encode(params, &mut param_buf);

                dst.reserve(Spdu::SI_SIZE + Spdu::LI_SIZE + param_buf.len());

                dst.put_u8(SpduId::Abort as u8);
                Spdu::encode_len(dst, param_buf.len());
                dst.put(param_buf);
            }

            Spdu::DataTransfer(_) => {
                dst.reserve(Spdu::SI_SIZE + 1);

                dst.put_u8(SpduId::DataTransfer as u8);
                dst.put_u8(0);
            }

            Spdu::GiveTokens(_) => {
                dst.reserve(Spdu::SI_SIZE + 1);

                // Give Tokens has the same SPDU ID (1) as Data Transfer
                dst.put_u8(SpduId::DataTransfer as u8);
                dst.put_u8(0);
            }
        }

        Ok(())
    }

    /// Deserialize the first SPDU from the input buffer
    pub fn decode(src: &mut Bytes) -> Result<Spdu, Error> {
        Spdu::decode_internal(src, None)
    }

    /// Deserialize concatenated SPDUs from the input buffer
    pub fn decode_next(src: &mut Bytes, prev_spdu: &Spdu) -> Result<Spdu, Error> {
        Spdu::decode_internal(src, Some(prev_spdu))
    }

    fn decode_internal(src: &mut Bytes, prev_spdu: Option<&Spdu>) -> Result<Spdu, Error> {
        // First byte is the SPDU Identifier
        let spdu_type = SpduId::try_from(src.try_get_u8()?).map_err(proto_err)?;
        let len = Spdu::decode_len(src)?;

        // Expect complete payload (note: len includes user data)
        if src.remaining() < len {
            return Err(Error::ProtocolError(format!(
                "Session: incomplete packet: expected {len}B, available {}B",
                src.remaining()
            )));
        }

        // Constrain decode to the SPDU length
        let mut src = src.take(len);

        // Perform packet specific decoding
        // Note that one or more Category 2 SPDUs may follow a single Category 0 SPDU,
        // while Category 1 SPDUs are one-to-one with the TSDU. See [X.225 Section 6.3.7]
        let spdu = match (spdu_type, prev_spdu) {
            (SpduId::Connect, None) => Spdu::Connect(ConnectParams::decode(&mut src)?),
            (SpduId::Accept, None) => Spdu::Accept(AcceptParams::decode(&mut src)?),
            (SpduId::Finish, None) => Spdu::Finish(FinishParams::decode(&mut src)?),
            (SpduId::Disconnect, None) => Spdu::Disconnect(DisconnectParams::decode(&mut src)?),
            (SpduId::Abort, None) => Spdu::Abort(AbortParams::decode(&mut src)?),
            (SpduId::DataTransfer, None) => Spdu::GiveTokens(GiveTokensParams::decode(&mut src)?),
            (SpduId::DataTransfer, Some(Spdu::GiveTokens(_))) => {
                Spdu::DataTransfer(DataTransferParams::decode(&mut src)?)
            }
            (si, None) => return Err(Error::ProtocolError(format!("Session: unsupported SPDU: {si:?}"))),
            (si, Some(prev)) => {
                return Err(Error::ProtocolError(format!(
                    "Session: unsupported SPDU sequence: {prev:?} --> {si:?}"
                )));
            }
        };

        Ok(spdu)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SessionParams {
    /// Sender's session address provided by SS-user
    pub local_session_selector: Option<Bytes>,
    /// Recipient's session address provided by SS-user
    pub remote_session_selector: Option<Bytes>,
}

/// Map a `num_enum::TryFromPrimitiveError` to the universal `Error` type.
fn proto_err<E>(err: TryFromPrimitiveError<E>) -> Error
where
    E: TryFromPrimitive,
{
    Error::ProtocolError(format!("Session: decode: {}", err))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors derived from public Wireshark captures:
    // https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/mms.pcap.gz
    // https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/x400-ping-success.pcap

    #[test]
    fn connect() {
        let user_data = hex::decode("3181a3a003800101a2819b80020780810400000001820400000002a423300f0201010604520100013004060251013010020103060528ca220201300406025101880206006160305e020101a059605780020780a107060528ca220101a20406022902a303020102a60406022901a703020101be32283006025101020103a027a82580027d00810114820114830104a416800101810305fb00820c036e1d000000000064000198").unwrap();
        let expected = hex::decode("0db4140200023302000134020002c1a63181a3a003800101a2819b80020780810400000001820400000002a423300f0201010604520100013004060251013010020103060528ca220201300406025101880206006160305e020101a059605780020780a107060528ca220101a20406022902a303020102a60406022901a703020101be32283006025101020103a027a82580027d00810114820114830104a416800101810305fb00820c036e1d000000000064000198").unwrap();

        let spdu = Spdu::Connect(ConnectParams {
            calling_session_selector: Some(Bytes::from_static(&[0x00, 0x01])),
            called_session_selector: Some(Bytes::from_static(&[0x00, 0x02])),
            user_data: Some(Bytes::from(user_data)),
        });

        let mut buf = BytesMut::new();
        Spdu::encode(&spdu, &mut buf).unwrap();

        assert_eq!(expected, buf.to_vec());

        let mut buf = buf.freeze();
        let spdu2 = Spdu::decode(&mut buf).unwrap();
        assert_eq!(spdu, spdu2);
    }

    #[test]
    fn connect_decode_complex() {
        let mut buf = Bytes::from(hex::decode("0dc4011d0a0a0408506572636976616c0b0f170d3035313030313134343835325a05091301001601021a010014020249c1943180a003800101a280a433300f020101060452010001300406025101300f02010306045600020c300406025101300f0201050604560002073004060251016150304e020101a0496047a106060456000106be3d283b06025101020103a032b03080013f820100a328a026b024a1228013706572636976616c2e736d68732e636f2e756ba10b1609657863616c6962757200000000").unwrap());
        let spdu = Spdu::decode(&mut buf).unwrap();

        if let Spdu::Connect(params) = spdu {
            assert_eq!(params.calling_session_selector, None);
            assert_eq!(params.called_session_selector, None);
            assert_eq!(
                params.user_data,
                Some(Bytes::from(hex::decode("3180a003800101a280a433300f020101060452010001300406025101300f02010306045600020c300406025101300f0201050604560002073004060251016150304e020101a0496047a106060456000106be3d283b06025101020103a032b03080013f820100a328a026b024a1228013706572636976616c2e736d68732e636f2e756ba10b1609657863616c6962757200000000").unwrap()
                ))
            );
        } else {
            panic!("unexpected SPDU type");
        }
    }

    #[test]
    fn accept() {
        let user_data = hex::decode("318184a003800101a27d80020780830400000002a512300780010081025101300780010081025101615d305b020101a056615480020780a107060528ca220101a203020100a305a103020100a40406022902a503020102be2e282c020103a027a92580027d00810114820114830104a416800101810305fb00820c036e1d000000000064000198").unwrap();
        let expected = hex::decode("0e8d14020002c187318184a003800101a27d80020780830400000002a512300780010081025101300780010081025101615d305b020101a056615480020780a107060528ca220101a203020100a305a103020100a40406022902a503020102be2e282c020103a027a92580027d00810114820114830104a416800101810305fb00820c036e1d000000000064000198").unwrap();

        let spdu = Spdu::Accept(AcceptParams {
            calling_session_selector: None,
            responding_session_selector: None,
            user_data: Some(Bytes::from(user_data)),
        });

        let mut buf = BytesMut::new();
        Spdu::encode(&spdu, &mut buf).unwrap();

        assert_eq!(expected, buf.to_vec());

        let mut buf = buf.freeze();
        let spdu2 = Spdu::decode(&mut buf).unwrap();
        assert_eq!(spdu, spdu2);
    }

    #[test]
    fn accept_decode_complex() {
        let mut buf = Bytes::from(hex::decode("0eb1011d090a0408506572636976616c0b0f170d3035313030313134343835325a05091301001601021a0100140202493400c17f317da003800101a276a51b30078001008102510130078001008102510130078001008102510161573055020101a050614ea106060456000106a203020100a305a103020100be38283606025101020103a02db12b80013fa226a024b122a12080146775696e65766572652e736d68732e636f2e756ba10816066d65726c696e").unwrap());
        let spdu = Spdu::decode(&mut buf).unwrap();

        if let Spdu::Accept(params) = spdu {
            assert_eq!(params.calling_session_selector, None);
            assert_eq!(params.responding_session_selector, Some(Bytes::new()));
            assert_eq!(
                params.user_data,
                Some(Bytes::from(hex::decode("317da003800101a276a51b30078001008102510130078001008102510130078001008102510161573055020101a050614ea106060456000106a203020100a305a103020100be38283606025101020103a02db12b80013fa226a024b122a12080146775696e65766572652e736d68732e636f2e756ba10816066d65726c696e").unwrap()))
            );
        } else {
            panic!("unexpected SPDU type");
        }
    }

    #[test]
    fn finish() {
        let user_data = hex::decode("deadbeef").unwrap();
        let expected = hex::decode("0906c104deadbeef").unwrap();

        let spdu = Spdu::Finish(FinishParams {
            user_data: Some(Bytes::from(user_data)),
        });

        let mut buf = BytesMut::new();
        Spdu::encode(&spdu, &mut buf).unwrap();

        assert_eq!(expected, buf.to_vec());

        let mut buf = buf.freeze();
        let spdu2 = Spdu::decode(&mut buf).unwrap();
        assert_eq!(spdu, spdu2);
    }

    #[test]
    fn finish_decode_complex() {
        let mut buf = Bytes::from(hex::decode("0913110101c10e610c300a020101a0056203800100").unwrap());
        let spdu = Spdu::decode(&mut buf).unwrap();

        if let Spdu::Finish(params) = spdu {
            assert_eq!(
                params.user_data,
                Some(Bytes::from(hex::decode("610c300a020101a0056203800100").unwrap()))
            );
        } else {
            panic!("unexpected SPDU type");
        }
    }

    #[test]
    fn disconnect() {
        let user_data = hex::decode("deadbeef").unwrap();
        let expected = hex::decode("0a06c104deadbeef").unwrap();

        let spdu = Spdu::Disconnect(DisconnectParams {
            user_data: Some(Bytes::from(user_data)),
        });

        let mut buf = BytesMut::new();
        Spdu::encode(&spdu, &mut buf).unwrap();

        assert_eq!(expected, buf.to_vec());

        let mut buf = buf.freeze();
        let spdu2 = Spdu::decode(&mut buf).unwrap();
        assert_eq!(spdu, spdu2);
    }

    #[test]
    fn abort() {
        let user_data = hex::decode("deadbeef").unwrap();
        let expected = hex::decode("190911010bc104deadbeef").unwrap();

        let spdu = Spdu::Abort(AbortParams {
            user_data: Some(Bytes::from(user_data)),
        });

        let mut buf = BytesMut::new();
        Spdu::encode(&spdu, &mut buf).unwrap();

        assert_eq!(expected, buf.to_vec());

        let mut buf = buf.freeze();
        let spdu2 = Spdu::decode(&mut buf).unwrap();
        assert_eq!(spdu, spdu2);
    }

    #[test]
    fn data_transfer() {
        let user_data = hex::decode("deadbeef").unwrap();
        let expected = hex::decode("01000100deadbeef").unwrap();

        let mut buf = BytesMut::new();
        Spdu::encode(&Spdu::GiveTokens(GiveTokensParams {}), &mut buf).unwrap();
        Spdu::encode(&Spdu::DataTransfer(DataTransferParams {}), &mut buf).unwrap();
        buf.put(user_data.as_slice());

        assert_eq!(expected, buf.to_vec());

        let mut buf = buf.freeze();

        let spdu1 = Spdu::decode(&mut buf).unwrap();
        assert!(matches!(spdu1, Spdu::GiveTokens(_)));

        let spdu2 = Spdu::decode_next(&mut buf, &spdu1).unwrap();
        assert!(matches!(spdu2, Spdu::DataTransfer(_)));

        assert_eq!(user_data, buf.to_vec());
    }
}
