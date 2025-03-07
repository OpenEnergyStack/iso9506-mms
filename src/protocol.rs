//! MMS protocol stack

pub mod acse;
pub mod presentation;
pub mod session;
pub mod tpkt;
pub mod transport;

pub(crate) mod mms; // Publically exported by lib.rs

use crate::error::Error;
use crate::messages::iso_9506_mms_1::MMSpdu;
use bytes::{Bytes, BytesMut};
use futures::{channel::mpsc, future, SinkExt, StreamExt};
use log::{trace, warn};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite};

pub type PDUSender = mpsc::Sender<MMSpdu>;
pub type PDUReceiver = mpsc::Receiver<MMSpdu>;

/// Configurable fields for various protocol layers.
/// Use default values unless interacting with an endpoint with specific requirements.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProtocolParams {
    pub transport: transport::TransportParams,
    pub session: session::SessionParams,
    pub presentation: presentation::PresentationParams,
}

/// Serialize an MMS PDU, adding on ACSE, Presentation, and Session layers.
/// Note that Transport layer framing is added separately.
pub fn encode(mpdu: &MMSpdu, pp: &ProtocolParams) -> Result<Bytes, Error> {
    let mut buf = BytesMut::new();

    match mpdu {
        // Associate request
        MMSpdu::initiate_RequestPDU(_) => {
            let mut session_data = BytesMut::new();

            // Encode ISO-8650 ACSE layer
            let apdu = acse::Apdu::pack_associate_request(&pp.presentation.acse_context_id, mpdu)?;

            trace!(
                "acse: encode associate request (AARQ), user-data context {} (ACSE)",
                pp.presentation.acse_context_id
            );

            // Encode ISO-8823 Presentation layer
            presentation::Ppdu::encode_connect(&pp.presentation, &apdu, &mut session_data)?;

            trace!(
                "presentation: encode connect (CP), user-data context {} (ACSE)",
                pp.presentation.acse_context_id
            );

            // Encode ISO-8327 Session layer
            let spdu = session::Spdu::Connect(session::ConnectParams {
                calling_session_selector: pp.session.local_session_selector.clone(),
                called_session_selector: pp.session.remote_session_selector.clone(),
                user_data: Some(session_data.freeze()),
            });
            session::Spdu::encode(&spdu, &mut buf)?;

            trace!(
                "session: encode connect (CN), calling session {:?}, called session {:?}",
                pp.session.local_session_selector,
                pp.session.remote_session_selector
            );
        }

        // Associate response
        MMSpdu::initiate_ResponsePDU(_) | MMSpdu::initiate_ErrorPDU(_) => {
            let mut session_data = BytesMut::new();

            // Encode ISO-8650 ACSE layer
            let apdu = acse::Apdu::pack_associate_response(&pp.presentation.acse_context_id, mpdu)?;

            trace!(
                "acse: encode associate response (AARE), user-data context {} (ACSE)",
                pp.presentation.acse_context_id
            );

            // Encode ISO-8823 Presentation layer
            presentation::Ppdu::encode_connect_accept(&pp.presentation, &apdu, &mut session_data)?;

            trace!(
                "presentation: encode connect accept (CPA), user-data context {} (ACSE)",
                pp.presentation.acse_context_id
            );

            // Encode ISO-8327 Session layer
            let spdu = session::Spdu::Accept(session::AcceptParams {
                calling_session_selector: pp.session.remote_session_selector.clone(),
                responding_session_selector: pp.session.local_session_selector.clone(),
                user_data: Some(session_data.freeze()),
            });
            session::Spdu::encode(&spdu, &mut buf)?;

            trace!(
                "session: encode accept (AC), calling session {:?}, responding session {:?}",
                pp.session.remote_session_selector,
                pp.session.local_session_selector
            );
        }

        // All other MMS PDUs are encoded with Data protocol primitives
        _ => {
            // Encode ISO-8327 Session layer (GiveTokens + DataTransfer SPDU sequence)
            let spdu = session::Spdu::GiveTokens(session::GiveTokensParams {});
            session::Spdu::encode(&spdu, &mut buf)?;
            let spdu = session::Spdu::DataTransfer(session::DataTransferParams {});
            session::Spdu::encode(&spdu, &mut buf)?;

            trace!("session: encode data transfer (GT + DT)");

            // Encode ISO-8823 Presentation layer with ISO-9506 MMS as user data
            presentation::Ppdu::encode_data_mms(&pp.presentation, mpdu, &mut buf)?;

            trace!(
                "presentation: encode user-data, context {} (MMS)",
                pp.presentation.mms_context_id
            );
        }
    }

    trace!("encoded {} bytes", buf.len());

    Ok(buf.freeze())
}

/// Deserialize Session, Presentation, and ACSE layers to extract an MMS PDU.
/// Note that Transport layer framing is handled separately.
pub fn decode(mut buf: Bytes, pp: &mut ProtocolParams) -> Result<MMSpdu, Error> {
    trace!("decode {} bytes", buf.len());

    // Decode ISO-8327 Session layer. All SPDUs other than DataTransfer
    // encode Presentation and Application layers in a User Data parameter.
    let spdu = session::Spdu::decode(&mut buf)?;

    let mpdu = match spdu {
        session::Spdu::Connect(params) => {
            trace!(
                "session: decoded connect (CN), calling session {:?}, called session {:?}",
                params.calling_session_selector,
                params.called_session_selector
            );

            buf = params
                .user_data
                .ok_or(Error::ProtocolError("Session: expect user data in Connect SPDU".into()))?;

            // Decode ISO-8823 Presentation layer
            let (p, apdu) = presentation::Ppdu::decode_connect(&mut buf)?;

            trace!(
                "presentation: decoded connect (CP), user-data context {} (ACSE)",
                p.acse_context_id
            );

            // Decode ISO-8650 ACSE layer
            let mpdu = acse::Apdu::unpack_associate_request(&pp.presentation.acse_context_id, &apdu)?;

            trace!(
                "acse: decoded associate request (AARQ), user-data context {} (ACSE)",
                pp.presentation.acse_context_id
            );

            // Update parameters for requested connection after successful decode
            pp.session.local_session_selector = params.called_session_selector;
            pp.session.remote_session_selector = params.calling_session_selector;
            pp.presentation = p;

            mpdu
        }

        session::Spdu::Accept(params) => {
            trace!(
                "session: decoded accept (AC), calling session {:?}, responding session {:?}",
                params.calling_session_selector,
                params.responding_session_selector
            );

            buf = params
                .user_data
                .ok_or(Error::ProtocolError("Session: expect user data in Accept SPDU".into()))?;

            // Decode ISO-8823 Presentation layer
            let apdu = presentation::Ppdu::decode_connect_accept(&pp.presentation, &mut buf)?;

            trace!(
                "presentation: decoded connect accept (CPA), user-data context {} (ACSE)",
                pp.presentation.acse_context_id
            );

            // Decode ISO-8650 ACSE layer
            let mpdu = acse::Apdu::unpack_associate_response(&pp.presentation.acse_context_id, &apdu)?;

            trace!(
                "acse: decoded associate response (AARE), user-data context {} (ACSE)",
                pp.presentation.acse_context_id
            );

            mpdu
        }

        session::Spdu::Disconnect(params) => {
            trace!("session: decode disconnect (DN)");

            buf = params.user_data.ok_or(Error::ProtocolError(
                "Session: expect user data in Disconnect SPDU".into(),
            ))?;

            // Decode ISO-8823 Presentation layer
            let apdu = presentation::Ppdu::decode_data_acse(&pp.presentation, &mut buf)?;

            trace!(
                "presentation: decoded user-data, context {} (ACSE)",
                pp.presentation.acse_context_id
            );

            // Decode ISO-8650 ACSE layer
            acse::Apdu::unpack_release_response(&apdu)?;

            trace!("acse: decoded release response (RLRE)");

            return Err(Error::ConnectionClosed);
        }

        session::Spdu::Finish(params) => {
            trace!("session: decoded finish (FN)");

            buf = params
                .user_data
                .ok_or(Error::ProtocolError("Session: expect user data in Finish SPDU".into()))?;

            // Decode ISO-8823 Presentation layer
            let apdu = presentation::Ppdu::decode_data_acse(&pp.presentation, &mut buf)?;

            trace!(
                "presentation: decoded user-data, context {} (ACSE)",
                pp.presentation.acse_context_id
            );

            // Decode ISO-8650 ACSE layer
            acse::Apdu::unpack_release_request(&apdu)?;

            trace!("acse: decoded release request (RLRQ)");

            return Err(Error::ConnectionClosed);
        }

        session::Spdu::Abort(params) => {
            trace!("session: decoded abort (AB)");

            buf = params
                .user_data
                .ok_or(Error::ProtocolError("Session: expect user data in Abort SPDU".into()))?;

            // Decode ISO-8823 Presentation layer
            let apdu = presentation::Ppdu::decode_abort_user(&pp.presentation, &mut buf)?;

            trace!(
                "presentation: decoded abnormal release (ARU), user-data context {} (ACSE)",
                pp.presentation.acse_context_id
            );

            // Decode ISO-8650 ACSE layer
            acse::Apdu::unpack_abort(&apdu)?;

            trace!("acse: decoded abort (ABRT)");

            return Err(Error::ConnectionClosed);
        }

        session::Spdu::DataTransfer(_) => unreachable!("Spdu::decode() should never return DataTransfer"),

        session::Spdu::GiveTokens(_) => {
            // User data follows GiveTokens + DataTransfer SPDU sequence
            session::Spdu::decode_next(&mut buf, &spdu)?;

            trace!("session: decoded data transfer (GT + DT)");

            // Decode ISO-8823 Presentation layer with ISO-9506 MMS as user data
            let mpdu = presentation::Ppdu::decode_data_mms(&pp.presentation, &mut buf)?;

            trace!(
                "presentation: decoded user-data, context {} (MMS)",
                pp.presentation.mms_context_id
            );

            mpdu
        }
    };

    Ok(mpdu)
}

/// Create a client-side protocol stack and return output and input channels
/// that accept application layer MMS PDUs.
pub async fn connect<S>(stream: S, params: ProtocolParams, buffer: usize) -> Result<(PDUSender, PDUReceiver), Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Read and write transport layer frames on top of TCP. See RFC-1006.
    let framed = tokio_util::codec::Framed::new(stream, tpkt::TpktCodec);

    // Negotiate a transport layer connection using Connection Oriented Transport Protocol.
    // See ISO-8073 and RFC-905.
    let connection = transport::connect(framed, params.transport.clone()).await?;

    // Input channel
    let (in_tx, in_rx) = mpsc::channel(buffer);

    // Output channel
    let (out_tx, out_rx) = mpsc::channel(buffer);

    tokio::spawn(async move {
        // Params contains state shared across protocol interactions
        let params: Arc<Mutex<ProtocolParams>> = Arc::new(Mutex::new(params));

        // Sink is the socket writer, stream is the socket reader
        let (mut sink, stream) = connection.split();

        // Encode outgoing MMS PDUs, adding protocol headers
        let out_params = params.clone();
        let mut out_encoded = out_rx.map(move |mpdu| encode(&mpdu, &out_params.lock().unwrap()));

        // channel -> socket
        let to_socket = sink.send_all(&mut out_encoded);

        // Decode incoming MMS PDUs, removing protocol headers
        let in_params = params.clone();
        let in_decoded = stream.map(move |frame| decode(frame?, &mut in_params.lock().unwrap()));

        // Convert `futures::mpsc::SendError` to `Error`
        let mut tx = in_tx.sink_map_err(Error::from);

        // channel <- socket
        let from_socket = in_decoded.forward(&mut tx);

        // Futures do not complete until shutdown or error
        match future::select(to_socket, from_socket).await {
            future::Either::Left((Err(err), _)) => warn!("PDU send failed: {err}"),
            future::Either::Right((Err(err), _)) => warn!("PDU receive failed: {err}"),
            _ => trace!("protocol stack shutdown"),
        }
    });

    // Return (out_tx, in_rx) pair so that the consumer can send and receive messages
    Ok((out_tx, in_rx))
}
