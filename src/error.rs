//! MMS errors

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Failed to decode an incoming BER encoded message
    #[error(transparent)]
    BerDecode(#[from] rasn::ber::de::DecodeError),

    /// Failed to encode an outgoing BER encoded message
    #[error(transparent)]
    BerEncode(#[from] rasn::ber::enc::EncodeError),

    /// Generic I/O error
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// RustTLS error
    #[error(transparent)]
    DnsName(#[from] rustls_pki_types::InvalidDnsNameError),

    /// RustTLS error
    #[error(transparent)]
    Tls(#[from] rustls::Error),

    /// Protocol stack error while processing incoming or outgoing message
    #[error("protocol error: {0}")]
    ProtocolError(String),

    /// Attempted to send an invalid request message
    #[error("bad request: {0:?}")]
    BadRequest(String),

    /// Received an invalid response message
    #[error("bad response: {0}")]
    BadResponse(String),

    /// Service interaction failed
    #[error("service error: {0:?}")]
    ServiceError(crate::messages::iso_9506_mms_1::ServiceError),

    /// Request timed out before completion
    #[error("request timed out")]
    Timeout,

    /// Request was canceled by the caller
    #[error("request canceled")]
    Canceled,

    /// Connection was closed due to network drop or a protocol error
    #[error("connection closed")]
    ConnectionClosed,
}

impl From<bytes::TryGetError> for Error {
    fn from(err: bytes::TryGetError) -> Self {
        Error::ProtocolError(format!(
            "incomplete packet: read {}B, available {}B",
            err.requested, err.available
        ))
    }
}

impl From<crate::messages::iso_9506_mms_1::ConfirmedErrorPDU> for Error {
    fn from(pdu: crate::messages::iso_9506_mms_1::ConfirmedErrorPDU) -> Self {
        Error::ServiceError(pdu.service_error)
    }
}

impl From<futures::channel::mpsc::SendError> for Error {
    fn from(_: futures::channel::mpsc::SendError) -> Self {
        Error::ConnectionClosed
    }
}

impl From<tokio::time::error::Elapsed> for Error {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        Error::Timeout
    }
}

impl std::fmt::Display for crate::messages::iso_9506_mms_1::RejectPDURejectReason {
    /// Error code mappings for RejectReason [ISO 9506-2:2003 Section 8.6].
    /// Integer codes are not provided by code generation.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::messages::iso_9506_mms_1::RejectPDURejectReason;

        write!(f, "{self:?}: ")?;

        match self {
            RejectPDURejectReason::confirmed_requestPDU(code) => match code {
                0 => write!(f, "other"),
                1 => write!(f, "unrecognized-service"),
                2 => write!(f, "unrecognized-modifier"),
                3 => write!(f, "invalid-invokeID"),
                4 => write!(f, "invalid-argument"),
                5 => write!(f, "invalid-modifier"),
                6 => write!(f, "max-serv-outstanding-exceeded"),
                // 7 reserved
                8 => write!(f, "max-recursion-exceeded"),
                9 => write!(f, "value-out-of-range"),
                _ => write!(f, "???"),
            },

            RejectPDURejectReason::confirmed_responsePDU(code) => match code {
                0 => write!(f, "other"),
                1 => write!(f, "unrecognized-service"),
                2 => write!(f, "invalid-invokeID"),
                3 => write!(f, "invalid-result"),
                // 4 reserved
                5 => write!(f, "max-recursion-exceeded"),
                6 => write!(f, "value-out-of-range"),
                _ => write!(f, "???"),
            },

            RejectPDURejectReason::confirmed_errorPDU(code) => match code {
                0 => write!(f, "other"),
                1 => write!(f, "unrecognized-service"),
                2 => write!(f, "invalid-invokeID"),
                3 => write!(f, "invalid-serviceError"),
                4 => write!(f, "value-out-of-range"),
                _ => write!(f, "???"),
            },

            RejectPDURejectReason::unconfirmedPDU(code) => match code {
                0 => write!(f, "other"),
                1 => write!(f, "unrecognized-service"),
                2 => write!(f, "invalid-argument"),
                3 => write!(f, "max-recursion-exceeded"),
                4 => write!(f, "value-out-of-range"),
                _ => write!(f, "???"),
            },

            RejectPDURejectReason::pdu_error(code) => match code {
                0 => write!(f, "unknown-pdu-type"),
                1 => write!(f, "invalid-pdu"),
                2 => write!(f, "illegal-acse-mapping"),
                _ => write!(f, "???"),
            },

            RejectPDURejectReason::cancel_requestPDU(code) => match code {
                0 => write!(f, "other"),
                1 => write!(f, "invalid-invokeID"),
                _ => write!(f, "???"),
            },

            RejectPDURejectReason::cancel_responsePDU(code) => match code {
                0 => write!(f, "other"),
                1 => write!(f, "invalid-invokeID"),
                _ => write!(f, "???"),
            },

            RejectPDURejectReason::cancel_errorPDU(code) => match code {
                0 => write!(f, "other"),
                1 => write!(f, "invalid-invokeID"),
                2 => write!(f, "invalid-serviceError"),
                3 => write!(f, "value-out-of-range"),
                _ => write!(f, "???"),
            },

            RejectPDURejectReason::conclude_requestPDU(code) => match code {
                0 => write!(f, "other"),
                1 => write!(f, "invalid-argument"),
                _ => write!(f, "???"),
            },

            RejectPDURejectReason::conclude_responsePDU(code) => match code {
                0 => write!(f, "other"),
                1 => write!(f, "invalid-result"),
                _ => write!(f, "???"),
            },

            RejectPDURejectReason::conclude_errorPDU(code) => match code {
                0 => write!(f, "other"),
                1 => write!(f, "invalid-serviceError"),
                2 => write!(f, "value-out-of-range"),
                _ => write!(f, "???"),
            },
        }
    }
}
