//! Implementation of ISO-8073 Transport Protocol Specification as described by
//! [RFC-905](https://datatracker.ietf.org/doc/html/rfc905). Functionality is divided into classes 0-4, which provide
//! additional features. This implementation covers Class 0, which includes basic
//! connection establishment, data transfer, and error reporting.

use std::{
    cmp::min,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt};
use log::trace;
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

use crate::error::Error;

/// TPDU type codes (Class 0 only) [RFC-905 Section 13.2.2.2]
#[derive(Clone, Copy, Debug, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum TpduType {
    ER = 0x70,
    DR = 0x80,
    CC = 0xd0,
    CR = 0xe0,
    DT = 0xf0,
}

/// TPDU parameter codes for CR and CC (Class 0 only) [RFC-905 Section 13.3.4]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum ConnectionParamCode {
    TpduSize = 0xc0,
    CallingTsap = 0xc1,
    CalledTsap = 0xc2,
}

/// TPDU size parameter values (Class 0 only) [RFC-905 Section 13.3.4]
/// Note that the encoded values may be converted to the actual max sizes with:
/// `1 << TpduSize::X as u8`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, TryFromPrimitive)]
#[repr(u8)]
pub enum TpduSize {
    #[default]
    Max128 = 0x07,
    Max256 = 0x08,
    Max512 = 0x09,
    Max1024 = 0x0a,
    Max2048 = 0x0b,
}

/// TPDU disconnect reason values (Class 0 only) [RFC-905 Section 13.5.3]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum DisconnectReason {
    NotSpecified = 0,
    Congestion = 1,
    SessionNotAttached = 2,
    AddressUnknown = 3,
}

/// TPDU reject cause values [RFC-905 Section 13.12.3]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum ErrorReason {
    NotSpecified = 0,
    InvalidParameterCode = 1,
    InvalidTpduType = 2,
    InvalidParameterValue = 3,
}

/// TPDU parameter codes for ER [RFC-905 Section 13.12.4]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum ErrorParamCode {
    InvalidTpdu = 0xc1,
}

/// Connection Request (CR) TPDU [RFC-905 Section 13.3]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionRequest {
    pub src_ref: u16,
    pub max_size: Option<TpduSize>,
    pub src_tsap_id: Option<Bytes>,
    pub dst_tsap_id: Option<Bytes>,
}

/// Connection Confirm (CC) TPDU [RFC-905 Section 13.4]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionConfirm {
    pub dst_ref: u16,
    pub src_ref: u16,
    pub max_size: Option<TpduSize>,
    pub src_tsap_id: Option<Bytes>,
    pub dst_tsap_id: Option<Bytes>,
}

/// Disonnect Request (DR) TPDU [RFC-905 Section 13.5]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisconnectRequest {
    pub dst_ref: u16,
    pub src_ref: u16,
    pub reason: DisconnectReason,
}

/// Data (DT) TPDU [RFC-905 Section 13.7]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataTransfer {
    pub end_of_transmission: bool,
}

/// TPDU Error (ER) TPDU [RFC-905 Section 13.12]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorResponse {
    pub dst_ref: u16,
    pub reason: ErrorReason,
    pub invalid_tpdu: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tpdu {
    CR(ConnectionRequest),
    CC(ConnectionConfirm),
    DR(DisconnectRequest),
    DT(DataTransfer),
    ER(ErrorResponse),
}

impl Tpdu {
    // Connection Request TPDU [RFC-905 Section 13.3.1]
    // 1    2        3        4       5   6    7    8    p  p+1...end
    // +--+------+---------+---------+---+---+------+-------+---------+
    // |LI|CR CDT|     DST - REF     |SRC-REF|CLASS |VARIAB.|USER     |
    // |  |1110  |0000 0000|0000 0000|   |   |OPTION|PART   |DATA     |
    // +--+------+---------+---------+---+---+------+-------+---------+
    //
    // Connection Confirm TPDU [RFC-905 Section 13.4.1]
    // 1      2     3   4   5   6     7     8     p   p+1 ...end
    // +---+----+---+---+---+---+---+-------+--------+-------------+
    // |LI | CC  CDT|DST-REF|SRC-REF| CLASS |VARIABLE| USER        |
    // |   |1101|   |   |   |   |   | OPTION|  PART  | DATA        |
    // +---+----+---+---+---+---+---+-------+--------+-------------+
    //
    // Disconnect Request TPDU [RFC-905 Section 13.5.1]
    // 1     2      3     4    5     6     7    8     p   p+1 ...end
    // +--+---------+----+-----+----+-----+------+--------+----------+
    // |LI|    DR   | DST-REF. | SRC-REF. |REASON|VARIABLE| USER     |
    // |  |1000 0001|    |     |    |     |      |  PART  | DATA     |
    // +--+---------+----+-----+----+-----+------+--------+----------+
    //
    // Data Transfer TPDU [RFC-905 Section 13.7.1]
    // 1       2         3          4       5             ... end
    // +----+-----------+-----------+------------ - - - - - -------+
    // | LI |    DT     |  TPDU-NR  | User Data                    |
    // |    | 1111 0000 |  and EOT  |                              |
    // +----+-----------+-----------+------------ - - - - - -------+
    //
    // Error TPDU [RFC-905 Section 13.12.1]
    // 1        2       3     4     5         6   P
    // +----+-----------+----+----+--------+----------+
    // | LI |    ER     | DST-REF | Reject | Variable |
    // |    | 0111 0000 |    |    | Cause  |   Part   |
    // +----+-----------+----+----+--------+----------+
    //
    // "Variable Part" consists of 0 or more segments composed of:
    // 1 byte code, 1 byte length, and N byte value [RFC-905 Section 13.2.3]
    //           Bits   8    7    6    5    4    3    2    1
    // Octets          +------------------------------------+
    //  n+1            |          Parameter Code            |
    //                 |------------------------------------|
    //  n+2            |          Parameter Length          |
    //                 |          Indication (e.g. m)       |
    //                 |------------------------------------|
    //  n+2+m          |          Parameter Value           |
    //                 |                ...                 |
    //                 +------------------------------------+

    /// Serialize TPDU to output buffer
    pub fn encode(tpdu: &Tpdu, dst: &mut BytesMut) -> Result<(), Error> {
        match tpdu {
            Tpdu::CR(cr) => {
                let fixed_len = 7;

                let variable_len = cr.max_size.as_ref().map_or(0, |_| 2 + 1)
                    + cr.src_tsap_id.as_ref().map_or(0, |id| 2 + id.len())
                    + cr.dst_tsap_id.as_ref().map_or(0, |id| 2 + id.len());

                let len = fixed_len + variable_len;

                dst.reserve(len);

                dst.put_u8(len as u8 - 1); // Length excludes length field [RFC-905 Section 13.2.1]
                dst.put_u8(TpduType::CR as u8);
                dst.put_u16(0);
                dst.put_u16(cr.src_ref);
                dst.put_u8(0);

                if let Some(size) = cr.max_size {
                    dst.put_u8(ConnectionParamCode::TpduSize as u8);
                    dst.put_u8(1);
                    dst.put_u8(size as u8);
                }

                if let Some(id) = cr.src_tsap_id.as_ref() {
                    dst.put_u8(ConnectionParamCode::CallingTsap as u8);
                    dst.put_u8(id.len() as u8);
                    dst.put(id.clone());
                }

                if let Some(id) = cr.dst_tsap_id.as_ref() {
                    dst.put_u8(ConnectionParamCode::CalledTsap as u8);
                    dst.put_u8(id.len() as u8);
                    dst.put(id.clone());
                }
            }

            Tpdu::CC(cc) => {
                let fixed_len = 7;

                let variable_len = cc.max_size.map_or(0, |_| 2 + 1);

                let len = fixed_len + variable_len;

                dst.reserve(len);

                dst.put_u8(len as u8 - 1); // Length excludes length field [RFC-905 Section 13.2.1]
                dst.put_u8(TpduType::CC as u8);
                dst.put_u16(cc.dst_ref);
                dst.put_u16(cc.src_ref);
                dst.put_u8(0);

                if let Some(size) = cc.max_size {
                    dst.put_u8(ConnectionParamCode::TpduSize as u8);
                    dst.put_u8(1);
                    dst.put_u8(size as u8);
                }
            }

            Tpdu::DR(dr) => {
                let fixed_len = 7;

                dst.reserve(fixed_len);

                dst.put_u8(fixed_len as u8 - 1); // Length excludes length field [RFC-905 Section 13.2.1]
                dst.put_u8(TpduType::DR as u8);
                dst.put_u16(dr.dst_ref);
                dst.put_u16(dr.src_ref);
                dst.put_u8(dr.reason as u8);
            }

            Tpdu::DT(dt) => {
                let fixed_len = 3;

                dst.reserve(fixed_len);

                dst.put_u8(fixed_len as u8 - 1); // Length excludes length field [RFC-905 Section 13.2.1]
                dst.put_u8(TpduType::DT as u8);
                // Bit 8 is the EOT bit. Bits 1-7 are 0 for Class 0 [RFC-905 Section 13.7.3]
                if dt.end_of_transmission {
                    dst.put_u8(0x80);
                } else {
                    dst.put_u8(0x00);
                }
            }

            Tpdu::ER(er) => {
                let fixed_len = 5;

                let variable_len = 2 + er.invalid_tpdu.len();

                let len = fixed_len + variable_len;

                dst.reserve(len);

                dst.put_u8(len as u8 - 1); // Length excludes length field [RFC-905 Section 13.2.1]
                dst.put_u8(TpduType::ER as u8);
                dst.put_u16(er.dst_ref);
                dst.put_u8(er.reason as u8);

                // Invalid TPDU parameter is mandatory in Class 0 [RFC-905 Section 13.12.4]
                dst.put_u8(ErrorParamCode::InvalidTpdu as u8);
                dst.put_u8(er.invalid_tpdu.len() as u8);
                dst.put(er.invalid_tpdu.clone());
            }
        }

        Ok(())
    }

    /// Extract and parse TPDU from input buffer
    pub fn decode(src: &mut Bytes) -> Result<Tpdu, Error> {
        // First byte is always length
        let len = src.try_get_u8()? as usize;

        // Expect complete packet
        if src.remaining() < len {
            return Err(Error::ProtocolError(format!(
                "Transport: incomplete packet: expected {len}B, available {}B",
                src.remaining()
            )));
        }

        // Extract entire packet from the buffer
        let mut src = src.split_to(len);

        let tpdu_type = TpduType::try_from(src.try_get_u8()?).map_err(proto_err)?;

        // Perform packet specific decoding
        let tpdu = match tpdu_type {
            // CR and CC have the same structure and parameters
            TpduType::CR | TpduType::CC => {
                let dst_ref = src.try_get_u16()?;
                let src_ref = src.try_get_u16()?;
                let _class = src.try_get_u8()?;

                let mut max_size = None;
                let mut src_tsap_id = None;
                let mut dst_tsap_id = None;

                while src.remaining() > 2 {
                    let param = ConnectionParamCode::try_from(src.get_u8()).map_err(proto_err)?;
                    let param_len = src.get_u8() as usize;

                    match param {
                        ConnectionParamCode::TpduSize => {
                            max_size = Some(TpduSize::try_from(src.get_u8()).map_err(proto_err)?)
                        }

                        ConnectionParamCode::CallingTsap => {
                            src_tsap_id = Some(src.split_to(min(param_len, src.remaining())));
                        }

                        ConnectionParamCode::CalledTsap => {
                            dst_tsap_id = Some(src.split_to(min(param_len, src.remaining())));
                        }
                    }
                }

                match tpdu_type {
                    TpduType::CR => Tpdu::CR(ConnectionRequest {
                        src_ref,
                        max_size,
                        src_tsap_id,
                        dst_tsap_id,
                    }),

                    TpduType::CC => Tpdu::CC(ConnectionConfirm {
                        dst_ref,
                        src_ref,
                        max_size,
                        src_tsap_id,
                        dst_tsap_id,
                    }),

                    _ => unreachable!("CR and CC handled in this block"),
                }
            }

            TpduType::DR => {
                let dst_ref = src.try_get_u16()?;
                let src_ref = src.try_get_u16()?;
                let reason = DisconnectReason::try_from(src.try_get_u8()?).map_err(proto_err)?;

                // Ignoring optional Additional Information parameter

                Tpdu::DR(DisconnectRequest {
                    dst_ref,
                    src_ref,
                    reason,
                })
            }

            TpduType::DT => {
                let seq = src.try_get_u8()?;
                let end_of_transmission = seq & 0x80 != 0;

                Tpdu::DT(DataTransfer { end_of_transmission })
            }

            TpduType::ER => {
                let dst_ref = src.try_get_u16()?;
                let reason = ErrorReason::try_from(src.try_get_u8()?).map_err(proto_err)?;

                let mut invalid_tpdu = Bytes::new();

                while src.remaining() > 2 {
                    let param = ErrorParamCode::try_from(src.get_u8()).map_err(proto_err)?;
                    let param_len = src.get_u8() as usize;

                    match param {
                        ErrorParamCode::InvalidTpdu => {
                            invalid_tpdu = src.split_to(min(param_len, src.remaining()));
                        }
                    }
                }

                Tpdu::ER(ErrorResponse {
                    dst_ref,
                    reason,
                    invalid_tpdu,
                })
            }
        };

        Ok(tpdu)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportParams {
    /// Sender's transport connection ID
    pub connection_id: u16,
    /// Maximum frame size (including header)
    pub max_tpdu_size: TpduSize,
    /// Local Transport Service Access Point identifier
    pub local_tsap_id: Bytes,
    /// Remote Transport Service Access Point identifier
    pub remote_tsap_id: Bytes,
}

impl Default for TransportParams {
    fn default() -> Self {
        Self {
            connection_id: 1,
            max_tpdu_size: TpduSize::Max2048,
            local_tsap_id: Bytes::from_static(&[0x00, 0x01]),
            remote_tsap_id: Bytes::from_static(&[0x00, 0x02]),
        }
    }
}

/// `Connection` wraps a codec for raw transport frames e.g. `TpktCodec` and
/// provides fragmentation and reassembly of Data Transfer TPDUs as described
/// by [RFC-905 Section 13.7.3]. Implementations of `Stream` and `Sync` traits
/// are provided to mirror the interface of the underlying codec.
pub struct Connection<C> {
    codec: C,
    max_tpdu_size: usize,
    stream_buf: BytesMut,
    sink_buf: BytesMut,
}

impl<C> Connection<C> {
    pub fn new(codec: C, max_tpdu_size: TpduSize) -> Self {
        Self {
            codec,
            max_tpdu_size: 1usize << max_tpdu_size as u8,
            stream_buf: BytesMut::new(),
            sink_buf: BytesMut::new(),
        }
    }
}

impl<C> Stream for Connection<C>
where
    C: Stream<Item = Result<Bytes, crate::error::Error>> + Unpin,
{
    type Item = Result<Bytes, crate::error::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.codec.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(mut frame))) => {
                    let tpdu = match Tpdu::decode(&mut frame) {
                        Ok(tpdu) => tpdu,
                        Err(err) => {
                            trace!("transport: TPDU decode error: {err}");
                            self.stream_buf.clear();
                            return Poll::Ready(Some(Err(err)));
                        }
                    };

                    trace!("transport: receive {tpdu:?}, payload {} bytes", frame.len());

                    match tpdu {
                        Tpdu::DT(dt) => {
                            // Large Data Transfers are fragmented to avoid exceeding max TPDU size
                            if dt.end_of_transmission {
                                if self.stream_buf.is_empty() {
                                    // Optimization: if transfer is in a single frame, no need to buffer
                                    return Poll::Ready(Some(Ok(frame)));
                                } else {
                                    // Received the last frame
                                    self.stream_buf.put(frame);
                                    return Poll::Ready(Some(Ok(self.stream_buf.split().freeze())));
                                }
                            } else {
                                // More frames expected; loop
                                self.stream_buf.put(frame);
                            }
                        }

                        _ => {
                            // All incoming TPDUs should be Data Transfer after connection is established
                            return Poll::Ready(Some(Err(Error::ProtocolError(format!(
                                "Transport: received {tpdu:?} during data transfer"
                            )))));
                        }
                    }
                }

                err @ Poll::Ready(Some(Err(_))) => {
                    return err;
                }

                none @ Poll::Ready(None) => {
                    if !self.stream_buf.is_empty() {
                        self.stream_buf.clear();
                        return Poll::Ready(Some(Err(Error::ProtocolError(
                            "Transport: stream closed during data transfer".to_string(),
                        ))));
                    }

                    return none;
                }

                pending @ Poll::Pending => {
                    return pending;
                }
            }
        }
    }
}

impl<C> Sink<Bytes> for Connection<C>
where
    C: Sink<Bytes, Error = crate::error::Error> + Unpin,
{
    type Error = crate::error::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.codec.poll_ready_unpin(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, mut item: Bytes) -> Result<(), Self::Error> {
        // All outgoing TPDUs should be Data Transfer after connection is established.
        // Large Data Transfers are fragmented to avoid exceeding max TPDU size.
        while item.has_remaining() {
            let dt_len = 3;
            let payload_len = min(item.remaining(), self.max_tpdu_size - dt_len);

            let tpdu = Tpdu::DT(DataTransfer {
                end_of_transmission: (payload_len == item.remaining()),
            });

            trace!("transport: send {tpdu:?}, payload {payload_len} bytes");

            Tpdu::encode(&tpdu, &mut self.sink_buf)?;
            self.sink_buf.put(item.split_to(payload_len));
        }

        let payload = self.sink_buf.split().freeze();

        self.codec.start_send_unpin(payload)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.codec.poll_flush_unpin(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.codec.poll_close_unpin(cx)
    }
}

/// Initiate a transport connection.
///
/// Note: always enforce a timeout as this async operation will not resume
/// until a response is received.
pub async fn connect<C>(mut codec: C, params: TransportParams) -> Result<Connection<C>, Error>
where
    C: Stream<Item = Result<Bytes, crate::error::Error>> + Sink<Bytes, Error = crate::error::Error> + Unpin,
{
    let req = Tpdu::CR(ConnectionRequest {
        src_ref: params.connection_id,
        max_size: Some(params.max_tpdu_size),
        src_tsap_id: Some(params.local_tsap_id),
        dst_tsap_id: Some(params.remote_tsap_id),
    });

    trace!("transport: send {req:?}");

    // Send Connection Request
    let mut buf = BytesMut::new();
    Tpdu::encode(&req, &mut buf)?;
    codec.send(buf.freeze()).await?;

    // Await Connection Confirm or error
    // Note: a response might never be received; the caller should set an appropriate timeout
    let mut buf = codec.next().await.ok_or(Error::ConnectionClosed)??;
    let resp = Tpdu::decode(&mut buf)?;

    trace!("transport: receive {resp:?}");

    match resp {
        Tpdu::CC(cc) => {
            let negotiated_max_size = min(params.max_tpdu_size, cc.max_size.unwrap_or_default());
            Ok(Connection::new(codec, negotiated_max_size))
        }
        tpdu => Err(Error::ProtocolError(format!("Transport: connection error: {tpdu:?}"))),
    }
}

/// Handle an incoming connection request.
///
/// Note that this is a trivial implementation that expects at most one
/// connection and does not track sufficient state to satisify the behavior
/// outlined in RFC-905. This is adequate for COTP layered on top of TCP,
/// as TCP is already connection-based.
#[allow(dead_code)]
pub async fn accept<C>(mut codec: C, params: TransportParams) -> Result<Connection<C>, Error>
where
    C: Stream<Item = Result<Bytes, crate::error::Error>> + Sink<Bytes, Error = crate::error::Error> + Unpin,
{
    // Await an incoming Connection Request
    loop {
        let mut buf = codec.next().await.ok_or(Error::ConnectionClosed)??;

        match Tpdu::decode(&mut buf) {
            Ok(tpdu) => {
                trace!("transport: receive {tpdu:?}");

                match tpdu {
                    Tpdu::CR(cr) => {
                        let negotiated_max_size = min(params.max_tpdu_size, cr.max_size.unwrap_or_default());

                        let cc = Tpdu::CC(ConnectionConfirm {
                            dst_ref: cr.src_ref,
                            src_ref: params.connection_id,
                            max_size: Some(negotiated_max_size),
                            src_tsap_id: None, // Note: reference implementations do not send TSAP-ID in CR
                            dst_tsap_id: None,
                        });

                        trace!("transport: send {cc:?}");

                        // Send Connection Confirm
                        let mut buf = BytesMut::new();
                        Tpdu::encode(&cc, &mut buf)?;
                        codec.send(buf.freeze()).await?;

                        return Ok(Connection::new(codec, negotiated_max_size));
                    }

                    Tpdu::DR(_) => {
                        // Already disconnected; ignore and continue to await connection requests
                        continue;
                    }

                    _ => {
                        return Err(Error::ProtocolError(format!(
                            "Transport: unexpected TPDU before connected: {tpdu:?}"
                        )));
                    }
                }
            }

            Err(err) => {
                trace!("transport: TPDU decode error: {err}");

                // TODO error response should be more specific.
                // Tpdu::decode() does not expose enough info at the moment.
                let er = Tpdu::ER(ErrorResponse {
                    dst_ref: 0,
                    reason: ErrorReason::NotSpecified,
                    invalid_tpdu: Bytes::new(),
                });

                trace!("transport: send {er:?}");

                let mut buf = BytesMut::new();
                Tpdu::encode(&er, &mut buf)?;
                codec.send(buf.freeze()).await?;

                return Err(err);
            }
        }
    }
}

/// Map a `num_enum::TryFromPrimitiveError` to the universal `Error` type.
fn proto_err<E>(err: TryFromPrimitiveError<E>) -> Error
where
    E: TryFromPrimitive,
{
    Error::ProtocolError(format!("Transport: decode: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors derived from public Wireshark captures:
    // https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/mms.pcap.gz

    #[test]
    fn connection_request() {
        let tpdu = Tpdu::CR(ConnectionRequest {
            src_ref: 0xb001,
            max_size: Some(TpduSize::Max1024),
            src_tsap_id: Some(Bytes::from_static(&[0x00, 0x01])),
            dst_tsap_id: Some(Bytes::from_static(&[0x00, 0x02])),
        });

        let expected = hex::decode("11e00000b00100c0010ac1020001c2020002").unwrap();

        let mut buf = BytesMut::new();
        Tpdu::encode(&tpdu, &mut buf).unwrap();

        assert_eq!(expected, buf.to_vec());

        let mut buf = buf.freeze();
        let tpdu2 = Tpdu::decode(&mut buf).unwrap();
        assert_eq!(tpdu, tpdu2);
    }

    #[test]
    fn connection_confirm() {
        let tpdu = Tpdu::CC(ConnectionConfirm {
            dst_ref: 0xb001,
            src_ref: 0x1802,
            max_size: Some(TpduSize::Max1024),
            src_tsap_id: None,
            dst_tsap_id: None,
        });

        let expected = hex::decode("09d0b001180200c0010a").unwrap();

        let mut buf = BytesMut::new();
        Tpdu::encode(&tpdu, &mut buf).unwrap();

        assert_eq!(expected, buf.to_vec());

        let mut buf = buf.freeze();
        let tpdu2 = Tpdu::decode(&mut buf).unwrap();
        assert_eq!(tpdu, tpdu2);
    }

    #[test]
    fn disconect_request() {
        let tpdu = Tpdu::DR(DisconnectRequest {
            dst_ref: 0xb001,
            src_ref: 0x1802,
            reason: DisconnectReason::Congestion,
        });

        let expected = hex::decode("0680b001180201").unwrap();

        let mut buf = BytesMut::new();
        Tpdu::encode(&tpdu, &mut buf).unwrap();

        assert_eq!(expected, buf.to_vec());

        let mut expected_plus_params = Bytes::from(hex::decode("1280b001180201e00a00010203040506070809").unwrap());

        let tpdu2 = Tpdu::decode(&mut expected_plus_params).unwrap();
        assert_eq!(tpdu, tpdu2);
    }

    #[test]
    fn data_transfer() {
        let tpdu = Tpdu::DT(DataTransfer {
            end_of_transmission: false,
        });

        let expected = hex::decode("02f000").unwrap();

        let mut buf = BytesMut::new();
        Tpdu::encode(&tpdu, &mut buf).unwrap();

        assert_eq!(expected, buf.to_vec());

        let mut buf = buf.freeze();
        let tpdu2 = Tpdu::decode(&mut buf).unwrap();
        assert_eq!(tpdu, tpdu2);
    }

    #[test]
    fn data_transfer_eot() {
        let tpdu = Tpdu::DT(DataTransfer {
            end_of_transmission: true,
        });

        let expected = hex::decode("02f080").unwrap();

        let mut buf = BytesMut::new();
        Tpdu::encode(&tpdu, &mut buf).unwrap();

        assert_eq!(expected, buf.to_vec());

        let mut buf = buf.freeze();
        let tpdu2 = Tpdu::decode(&mut buf).unwrap();
        assert_eq!(tpdu, tpdu2);
    }

    #[test]
    fn error_response() {
        let tpdu = Tpdu::ER(ErrorResponse {
            dst_ref: 0xb001,
            reason: ErrorReason::InvalidTpduType,
            invalid_tpdu: Bytes::from_static(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
        });

        let expected = hex::decode("1070b00102c10a00010203040506070809").unwrap();

        let mut buf = BytesMut::new();
        Tpdu::encode(&tpdu, &mut buf).unwrap();

        assert_eq!(expected, buf.to_vec());

        let mut buf = buf.freeze();
        let tpdu2 = Tpdu::decode(&mut buf).unwrap();
        assert_eq!(tpdu, tpdu2);
    }

    // TODO add test coverage for connect() and accept()
}
