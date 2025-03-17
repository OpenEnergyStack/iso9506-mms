//! Implements ISO-8072 Transport Service on top of TCP
//!
//! This adds trivial framing to the existing stream transport as
//! described by [RFC-1006 Section 6](https://datatracker.ietf.org/doc/html/rfc1006#section-6):
//!
//! A TPKT consists of two parts:  a packet-header and a TPDU.  The
//! format of the header is constant regardless of the type of packet.
//! The format of the packet-header is as follows:
//! ```text
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |      vrsn     |    reserved   |          packet length        |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//! where:
//!
//! vrsn                         8 bits
//!
//! This field is always 3 for the version of the protocol described in
//! this memo.
//!
//! packet length                16 bits (min=7, max=65535)
//!
//! This field contains the length of entire packet in octets,
//! including packet-header.  This permits a maximum TPDU size of
//! 65531 octets.  Based on the size of the data transfer (DT) TPDU,
//! this permits a maximum TSDU size of 65524 octets.

use crate::error::Error;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

const HEADER_VERSION: u8 = 3;
const HEADER_LEN: usize = 4;
const PAYLOAD_MAX: usize = 65531;

pub struct TpktCodec;

impl Decoder for TpktCodec {
    type Item = Bytes;
    type Error = Error;

    /// Deserialize TPKT frames from an input stream.
    /// See discussion on [`Decoder`](https://docs.rs/tokio-util/latest/tokio_util/codec/index.html#the-decoder-trait) implementation.
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < HEADER_LEN {
            return Ok(None);
        }

        let mut header = &src[..HEADER_LEN];

        // Version
        let version = header.get_u8();

        if version != HEADER_VERSION {
            return Err(Error::ProtocolError(format!(
                "TPKT version mismatch: expected {HEADER_VERSION}, received {version}"
            )));
        }

        // Reserved
        header.advance(1);

        // Packet Length, big endian
        let len = header.get_u16() as usize;

        if len < HEADER_LEN {
            return Err(Error::ProtocolError("TPKT length invalid".into()));
        }

        if len > src.remaining() {
            // Optimization: if fragmented, pre-allocate enough space for the remainder of the packet
            src.reserve(len - src.remaining());
            return Ok(None);
        }

        // Payload
        let payload = src.split_to(len).split_off(HEADER_LEN).freeze();

        Ok(Some(payload))
    }
}

impl Encoder<Bytes> for TpktCodec {
    type Error = Error;

    /// Serializes TPKT frames to an output stream.
    /// See discussion on [`Encoder`](https://docs.rs/tokio-util/latest/tokio_util/codec/index.html#the-encoder-trait) implementation.
    fn encode(&mut self, payload: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if payload.len() > PAYLOAD_MAX {
            return Err(Error::ProtocolError(format!(
                "TPKT payload exceeds max len: {PAYLOAD_MAX}B"
            )));
        }

        let len = HEADER_LEN + payload.len();

        dst.reserve(len);

        // Version
        dst.put_u8(HEADER_VERSION);

        // Reserved
        dst.put_u8(0);

        // Packet Length, big endian
        dst.put_u16(len as u16);

        // Payload
        dst.put(payload);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode() {
        let payload = Bytes::from_static(b"data");
        let mut buf = BytesMut::new();

        let res = TpktCodec {}.encode(payload, &mut buf);

        assert!(res.is_ok());
        assert_eq!(buf[..], [0x03, 0x00, 0x00, 0x08, 0x64, 0x61, 0x74, 0x61]);
    }

    #[test]
    fn decode_exact() {
        let bytes: &[u8] = &[0x03, 0x00, 0x00, 0x08, 0x64, 0x61, 0x74, 0x61];
        let mut buf = BytesMut::from(bytes);

        let res = TpktCodec {}.decode(&mut buf);

        let payload = res.expect("ok").expect("payload");

        assert_eq!(&payload[..], b"data");
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn decode_short() {
        let bytes: &[u8] = &[0x03, 0x00, 0x00, 0x08, 0x64, 0x61, 0x74];
        let mut buf = BytesMut::from(bytes);

        let res = TpktCodec {}.decode(&mut buf);

        let res = res.expect("ok");

        assert!(res.is_none());
        assert_eq!(buf.remaining(), bytes.len());
    }

    #[test]
    fn decode_long() {
        let bytes: &[u8] = &[0x03, 0x00, 0x00, 0x08, 0x64, 0x61, 0x74, 0x61, 0xff];
        let mut buf = BytesMut::from(bytes);

        let res = TpktCodec {}.decode(&mut buf);

        let payload = res.expect("ok").expect("payload");

        assert_eq!(&payload[..], b"data");
        assert_eq!(&buf[..], &[0xff]);
    }

    #[test]
    fn decode_unsupported_version() {
        let bytes: &[u8] = &[0x02, 0x00, 0x00, 0x08, 0x64, 0x61, 0x74, 0x61];
        let mut buf = BytesMut::from(bytes);

        let res = TpktCodec {}.decode(&mut buf);

        assert!(matches!(res, Err(Error::ProtocolError(_))));
    }
}
