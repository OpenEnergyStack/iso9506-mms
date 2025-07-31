//! MMS client

pub mod variable_access;
pub mod vmd_support;

use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures::{SinkExt, StreamExt, channel::mpsc};
use log::{debug, error, trace, warn};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use tokio::sync::broadcast;

use crate::{
    bitstring,
    error::Error,
    messages::{iso_9506_mms_1::*, mms_object_module_1::*},
    protocol::{self, PDUReceiver, PDUSender, mms::*},
};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const CHANNEL_SIZE: usize = 64;

/// Configuration for TLS connections
#[derive(Clone, Debug)]
pub struct TLSConfig {
    config: Arc<rustls::ClientConfig>,
    domain_name: Option<String>,
}

impl TLSConfig {
    pub fn new(config: rustls::ClientConfig) -> Self {
        Self {
            config: Arc::new(config),
            domain_name: None,
        }
    }

    pub fn domain_name(mut self, domain_name: String) -> Self {
        self.domain_name = Some(domain_name);
        self
    }
}

impl Default for TLSConfig {
    /// Default TLS configuration loads CA certs from the host system
    /// and does not enable client authentication.
    fn default() -> Self {
        use rustls_platform_verifier::ConfigVerifierExt;

        Self::new(rustls::ClientConfig::with_platform_verifier())
    }
}

/// Builder object for a `Client`
pub struct Builder {
    timeout: Duration,
    tls_config: Option<TLSConfig>,
}

impl Builder {
    /// Override the default connect timeout
    pub fn timeout_after(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Enable TLS
    pub fn use_tls(mut self, config: TLSConfig) -> Self {
        self.tls_config = Some(config);
        self
    }

    /// Connect to an MMS server and return start a `Client` on the connection.
    // TODO is this a good pattern for reconnect?
    pub async fn connect(self, host: impl AsRef<str>, port: u16) -> Result<Client, Error> {
        use tokio::net;

        // Timeout spans hostname lookup, TCP connect, TLS negotiation, and session start
        tokio::time::timeout(self.timeout, async {
            let host = host.as_ref();

            debug!("resolving host: {host}:{port}");

            // DNS lookup
            let addrs = net::lookup_host((host, port)).await?.collect::<Vec<_>>();
            let addr = addrs.first().ok_or(io::Error::from(io::ErrorKind::HostUnreachable))?;

            trace!("found: {addrs:?}");
            debug!("connecting to {addr}");

            // Connect to TCP server
            let stream = net::TcpStream::connect(&addr).await?;

            debug!("TCP connected");

            // Instatiate a protocol stack that accepts MMS PDUs and handles
            // lower level networking functions.
            let params = protocol::ProtocolParams::default();
            let channel = match self.tls_config {
                Some(tls) => {
                    use rustls_pki_types::ServerName;

                    let domain = ServerName::try_from(tls.domain_name.unwrap_or(host.to_string()).to_owned())?;

                    debug!("performing TLS handshake, SNI: {domain:?}");

                    let tokio_connector = tokio_rustls::TlsConnector::from(tls.config);
                    let stream = tokio_connector.connect(domain, stream).await?;

                    debug!("TLS handshake succeeded");

                    protocol::connect(stream, params, CHANNEL_SIZE).await?
                }

                None => protocol::connect(stream, params, CHANNEL_SIZE).await?,
            };

            Client::start(channel).await
        })
        .await?
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_CONNECT_TIMEOUT,
            tls_config: None,
        }
    }
}

type RequestMap = HashMap<u32, PDUSender>;

/// MMS client
#[derive(Clone)]
pub struct Client {
    sender: PDUSender,
    requests: Arc<Mutex<RequestMap>>,
    unconfirmed: broadcast::Sender<UnconfirmedService>,
    rng: Arc<Mutex<StdRng>>,
}

impl Client {
    /// Returns a builder to configure a TCP connection and create a `Client`.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Internal function to create a `Client` from an channel-pair that sends
    /// and received application layer MMS PDUs. This decouples the `Client`
    /// from the lower level protocol stack and facilitates testing.
    async fn start(mut channel: (PDUSender, PDUReceiver)) -> Result<Client, Error> {
        // Initiate logical session with server prior to starting
        Client::initiate(&mut channel).await?;

        let (sender, mut receiver) = channel;

        let client = Client {
            sender,
            requests: Arc::new(Mutex::new(HashMap::new())),
            unconfirmed: broadcast::Sender::new(CHANNEL_SIZE),
            rng: Arc::new(Mutex::new(StdRng::from_os_rng())),
        };

        let requests = client.requests.clone();
        let unconfirmed = client.unconfirmed.clone();

        // Start a task to process incoming messages
        tokio::spawn(async move {
            while let Some(pdu) = receiver.next().await {
                // Evaluate incoming response PDUs and route them to the appropriate
                // `PendingRequest`. See [ISO 9506-2:2003 Section 6.3.1.1] for
                // expected message flows from the client's perspective.
                match &pdu {
                    MMSpdu::confirmed_ResponsePDU(resp) => {
                        if let Some(mut sender) = requests.lock().ok().and_then(|mut r| r.remove(&resp.invoke_id.0)) {
                            let _ = sender.send(pdu).await;
                        } else {
                            trace!(
                                "dropping Confirmed-Response: no pending request for invoke ID {}",
                                resp.invoke_id.0
                            );
                        }
                    }

                    MMSpdu::confirmed_ErrorPDU(err) => {
                        if let Some(mut sender) = requests.lock().ok().and_then(|mut r| r.remove(&err.invoke_id.0)) {
                            let _ = sender.send(pdu).await;
                        } else {
                            trace!(
                                "dropping Confirmed-Error: no pending request for invoke ID {}",
                                err.invoke_id.0
                            );
                        }
                    }

                    MMSpdu::unconfirmed_PDU(unconf) => {
                        let _ = unconfirmed.send(unconf.to_owned().service);
                    }

                    MMSpdu::rejectPDU(rej) => {
                        if let Some(mut sender) = rej
                            .original_invoke_id
                            .as_ref()
                            .and_then(|id| requests.lock().ok().and_then(|mut r| r.remove(&id.0)))
                        {
                            let _ = sender.send(pdu).await;
                        } else {
                            warn!("received Reject message: {}", rej.reject_reason);
                        }
                    }

                    MMSpdu::cancel_ResponsePDU(resp) => {
                        if let Some(mut sender) = requests.lock().ok().and_then(|mut r| r.remove(&resp.0.0)) {
                            let _ = sender.send(pdu).await;
                        } else {
                            trace!(
                                "dropping Cancel-Response: no pending request for invoke ID {}",
                                resp.0.0
                            );
                        }
                    }

                    MMSpdu::cancel_ErrorPDU(err) => {
                        // Not removing request entry on cancellation error as request is still pending
                        if let Some(mut sender) = requests
                            .lock()
                            .ok()
                            .and_then(|r| r.get(&err.original_invoke_id.0).cloned())
                        {
                            let _ = sender.send(pdu).await;
                        } else {
                            trace!(
                                "dropping Cancel-Error: no pending request for invoke ID {}",
                                err.original_invoke_id.0
                            );
                        }
                    }

                    _ => trace!("dropping unexpected PDU: {pdu:?}"),
                }
            }

            // Cancel pending requests on disconnect
            if let Ok(mut requests) = requests.lock() {
                requests.clear();
            }

            trace!("connection closed");
        });

        Ok(client)
    }

    /// Returns true if the connection to the server is up.
    pub fn is_connected(&self) -> bool {
        !self.sender.is_closed()
    }

    /// Low-level API to send a Confirmed Request and await the response.
    /// This function returns a [PendingRequest] object that can be used to await
    /// the response or cancel the request.
    ///
    /// Note: for short-running requests, prefer [Client::request()], as it has
    /// streamlined usage.
    ///
    /// # Example
    /// ```
    /// # use mms::{client::*, *};
    /// # async fn test() -> Result<(), Error> {
    /// let client = Client::builder().connect("localhost", 102).await?;
    ///
    /// let req = ConfirmedServiceRequest::identify(IdentifyRequest(()));
    /// let pending = client.start_request(req, None).await?;
    /// let resp = pending.response().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn start_request(
        &self,
        req: ConfirmedServiceRequest,
        modifiers: Option<Vec<Modifier>>,
    ) -> Result<PendingRequest, Error> {
        let invoke_id = self.next_invoke_id();

        let pdu = MMSpdu::confirmed_RequestPDU(ConfirmedRequestPDU {
            invoke_id: Unsigned32(invoke_id),
            list_of_modifiers: modifiers,
            service: req,
        });

        // Send the request.
        // Note: creating a temporary clone of the sender to avoid mutating the `Client`.
        // This allows this function to accept a constant reference to `self`, which
        // in turn enables a single `Client` to perform multiple concurrent requests.
        // If `self` were mutable, the borrow checker would force serialization of
        // requests, because it only allows one mutable reference at a time, and the
        // lifetime of `&mut self` would extend until the returned Future was ready.
        self.sender.clone().send(pdu).await?;

        // Using buffer size two, as no more than one response and one cancel-related
        // message should be received for a request. Additional messages are violations
        // of the protocol and channel backpressure is preferable to buffering.
        let (resp_tx, resp_rx) = mpsc::channel(2);

        // Add an entry to route response messages back to this `PendingRequest`.
        self.requests.lock().unwrap().insert(invoke_id, resp_tx);

        Ok(PendingRequest {
            invoke_id,
            receiver: resp_rx,
            requests: self.requests.clone(),
        })
    }

    /// Low-level API to cancel a [PendingRequest].
    pub async fn cancel_request(&self, mut pending: PendingRequest) -> Result<(), Error> {
        let pdu = MMSpdu::cancel_RequestPDU(CancelRequestPDU(Unsigned32(pending.invoke_id)));

        self.sender.clone().send(pdu).await?;

        match pending.receiver.next().await {
            Some(pdu) => match pdu {
                // Upon successful cancellation, a Cancel-Response and a Confirmed-Error
                // may be received in any order [ISO 9506-2:2003 Section 6.3.1.1]
                MMSpdu::confirmed_ErrorPDU(_) | MMSpdu::cancel_ResponsePDU(_) => Ok(()),

                // Invalid or unsupported Cancel-Request
                MMSpdu::rejectPDU(rej) => Err(Error::BadRequest(format!("{}", rej.reject_reason))),

                // Cancel-Error or Confirmed-Response indicates cancellation failed
                // or was preempted
                _ => Err(Error::Canceled),
            },
            None => Err(Error::ConnectionClosed),
        }
    }

    /// Low-level API to send a Confirmed Request and await the response.
    ///
    /// Note: this async call times out after 15s. To override this timeout,
    /// use [Client::request_with_timeout()].
    ///
    /// # Example
    /// ```
    /// # use mms::{client::*, *};
    /// # async fn test() -> Result<(), Error> {
    /// let client = Client::builder().connect("localhost", 102).await?;
    ///
    /// let req = ConfirmedServiceRequest::identify(IdentifyRequest(()));
    /// let resp = client.request(req, None).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn request(
        &self,
        req: ConfirmedServiceRequest,
        modifiers: Option<Vec<Modifier>>,
    ) -> Result<ConfirmedServiceResponse, Error> {
        self.request_with_timeout(req, modifiers, DEFAULT_REQUEST_TIMEOUT).await
    }

    /// Like [Client::request()], but with an explicit timeout.
    pub async fn request_with_timeout(
        &self,
        req: ConfirmedServiceRequest,
        modifiers: Option<Vec<Modifier>>,
        timeout: Duration,
    ) -> Result<ConfirmedServiceResponse, Error> {
        // Timeout spans send and receive async operations
        tokio::time::timeout(timeout, async {
            let pending = self.start_request(req, modifiers).await?;

            pending.response().await
        })
        .await?
    }

    /// Subscribe to incoming Unconfirmed messages.
    ///
    /// # Example
    /// ```
    /// # use mms::{client::*, *};
    /// # async fn test() -> Result<(), Error> {
    /// let client = Client::builder().connect("localhost", 102).await?;
    ///
    /// let mut handler = client.handle_unconfirmed();
    ///
    /// while let Ok(unconf) = handler.recv().await {
    ///     println!("received {unconf:?}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn handle_unconfirmed(&self) -> broadcast::Receiver<UnconfirmedService> {
        self.unconfirmed.subscribe()
    }

    /// Initiate a session with the MMS server. This is a required protocol
    /// interaction prior to other message exchanges.
    async fn initiate(channel: &mut (PDUSender, PDUReceiver)) -> Result<(), Error> {
        let (sender, receiver) = channel;

        // The ASN.1 schemas used for code generation include parameters
        // for all Conformance Building Blocks.
        let cbb = ParameterSupportOptions(bitstring!(
            ParameterSupportOptionsBit::Str1,
            ParameterSupportOptionsBit::Str2,
            ParameterSupportOptionsBit::Vnam,
            ParameterSupportOptionsBit::Valt,
            ParameterSupportOptionsBit::Vadr,
            ParameterSupportOptionsBit::Vsca,
            ParameterSupportOptionsBit::Tpy,
            ParameterSupportOptionsBit::Vlis,
            ParameterSupportOptionsBit::Cei
        ));

        // Flags for all implemented services (implementations below).
        let services = ServiceSupportOptions(bitstring!(
            // VMD Support
            ServiceSupportOptionsBit::Status,
            ServiceSupportOptionsBit::GetNameList,
            ServiceSupportOptionsBit::Identify,
            ServiceSupportOptionsBit::Rename,
            ServiceSupportOptionsBit::GetCapabilityList,
            // Variable Access
            ServiceSupportOptionsBit::Read,
            ServiceSupportOptionsBit::Write,
            ServiceSupportOptionsBit::GetVariableAccessAttributes,
            ServiceSupportOptionsBit::DefineNamedVariable,
            ServiceSupportOptionsBit::DeleteVariableAccess,
            ServiceSupportOptionsBit::DefineNamedVariableList,
            ServiceSupportOptionsBit::GetNamedVariableListAttributes,
            ServiceSupportOptionsBit::DeleteNamedVariableList,
            ServiceSupportOptionsBit::DefineNamedType,
            ServiceSupportOptionsBit::GetNamedTypeAttributes,
            ServiceSupportOptionsBit::DeleteNamedType
        ));

        // Several parameters are hard-coded below. This client is not expected
        // to be severely resource-limited, so generous limits are proposed.
        let req = InitiateRequestPDU {
            local_detail_calling: None,
            proposed_max_serv_outstanding_called: Integer16(128),
            proposed_max_serv_outstanding_calling: Integer16(128),
            proposed_data_structure_nesting_level: None,
            init_request_detail: InitiateRequestPDUInitRequestDetail {
                proposed_version_number: Integer16(1),
                proposed_parameter_cbb: cbb,
                services_supported_calling: services,
            },
        };

        debug!("initiating MMS session");

        sender.send(MMSpdu::initiate_RequestPDU(req)).await?;

        if let Some(pdu) = receiver.next().await {
            match pdu {
                MMSpdu::initiate_ResponsePDU(_) => {
                    debug!("MMS session started");

                    Ok(())
                }

                MMSpdu::initiate_ErrorPDU(err) => {
                    error!("received Initiate-Error: {err:?}");
                    Err(Error::ConnectionClosed)
                }

                _ => {
                    error!("received unexpected PDU during Initiate sequence: {pdu:?}");
                    Err(Error::BadResponse(
                        "received unexpected PDU during Initiate sequence".into(),
                    ))
                }
            }
        } else {
            Err(Error::ConnectionClosed)
        }
    }

    /// Generate Confirmed request invoke IDs using a pseudo-random number generator.
    /// This is preferable over a simple sequential counter as it reduces the
    /// likelihood of invoke ID collisions if clients are restarted.
    fn next_invoke_id(&self) -> u32 {
        self.rng.lock().unwrap().next_u32()
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("connected", &!self.sender.is_closed())
            .field("pending", &self.requests.lock().iter().len())
            .finish()
    }
}

/// Handle to a pending Confirmed request. This is returned by [Client::start_request()].
pub struct PendingRequest {
    invoke_id: u32,
    receiver: PDUReceiver,
    requests: Arc<Mutex<RequestMap>>,
}

impl PendingRequest {
    /// Await the response to a Confirmed request message.
    /// Note: it is up to the caller to apply a reasonable timeout for this async operation.
    pub async fn response(mut self) -> Result<ConfirmedServiceResponse, Error> {
        let rx = &mut self.receiver;

        loop {
            match rx.next().await {
                Some(pdu) => match pdu {
                    MMSpdu::confirmed_ResponsePDU(resp) => break Ok(resp.service),
                    MMSpdu::confirmed_ErrorPDU(err) => break Err(Error::from(err)),
                    MMSpdu::rejectPDU(rej) => break Err(Error::BadRequest(format!("{}", rej.reject_reason))),
                    _ => {
                        // Ignore Cancel-Response and Cancel-Error here, because
                        // both cancellation and awaiting the response consume
                        // the PendingRequest, guaranteeing mutal exclusion.
                        // In other words, we cannot be here if the client
                        // requested cancellation, and if the client did not
                        // request cancellation, these messages are unexpected
                        // and should be dropped.
                        trace!("dropping unexpected PDU: {pdu:?}");
                        continue;
                    }
                },
                None => break Err(Error::ConnectionClosed),
            }
        }
    }
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        if let Ok(mut requests) = self.requests.lock() {
            requests.remove(&self.invoke_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use rand::seq::SliceRandom;
    use rasn::types::{FixedBitString, VisibleString};

    use super::*;
    use crate::messages::iso_9506_mms_1_a::*;

    fn make_initiate_resp_pdu() -> MMSpdu {
        MMSpdu::initiate_ResponsePDU(InitiateResponsePDU {
            local_detail_called: None,
            negotiated_max_serv_outstanding_calling: Integer16(1),
            negotiated_max_serv_outstanding_called: Integer16(1),
            negotiated_data_structure_nesting_level: None,
            init_response_detail: InitiateResponsePDUInitResponseDetail {
                negotiated_version_number: Integer16(1),
                negotiated_parameter_cbb: ParameterSupportOptions(FixedBitString::ZERO),
                services_supported_called: ServiceSupportOptions(FixedBitString::ZERO),
            },
        })
    }

    fn make_reject_pdu(invoke_id: Option<Unsigned32>) -> MMSpdu {
        MMSpdu::rejectPDU(RejectPDU {
            original_invoke_id: invoke_id,
            reject_reason: RejectPDURejectReason::pdu_error(1),
        })
    }

    fn make_req(id: u32) -> ConfirmedServiceRequest {
        // Arbitrary request type for testing
        ConfirmedServiceRequest::fileRead(FileReadRequest(Integer32(id as i32)))
    }

    fn make_resp(id: u32) -> ConfirmedServiceResponse {
        let mut data = BytesMut::new();
        data.put_u32(id);

        ConfirmedServiceResponse::fileRead(FileReadResponse {
            file_data: data.freeze(),
            more_follows: false,
        })
    }

    fn make_err() -> ServiceError {
        ServiceError {
            error_class: ServiceErrorErrorClass::service(0),
            additional_code: None,
            additional_description: Some(VisibleString::try_from("the system is down").unwrap()),
            service_specific_info: None,
        }
    }

    fn make_resp_pdu(invoke_id: Unsigned32, resp: ConfirmedServiceResponse) -> MMSpdu {
        MMSpdu::confirmed_ResponsePDU(ConfirmedResponsePDU {
            invoke_id,
            service: resp,
        })
    }

    fn make_err_pdu(invoke_id: Unsigned32, err: ServiceError) -> MMSpdu {
        MMSpdu::confirmed_ErrorPDU(ConfirmedErrorPDU {
            invoke_id,
            modifier_position: None,
            service_error: err,
        })
    }

    fn make_unconfirmed_pdu(status: u8) -> MMSpdu {
        MMSpdu::unconfirmed_PDU(UnconfirmedPDU {
            service: UnconfirmedService::unsolicitedStatus(UnsolicitedStatus(Status {
                vmd_logical_status: status,
                vmd_physical_status: status,
                local_detail: None,
            })),
        })
    }

    #[tokio::test]
    async fn single_request() {
        let req = make_req(123);
        let expected_req = req.clone();

        let resp = make_resp(123);
        let expected_resp = resp.clone();

        // Channel
        let (out_tx, mut out_rx) = futures::channel::mpsc::channel(1);
        let (mut in_tx, in_rx) = futures::channel::mpsc::channel(1);
        let channel = (out_tx, in_rx);

        // Server
        tokio::spawn(async move {
            while let Some(pdu) = out_rx.next().await {
                let resp = match pdu {
                    MMSpdu::initiate_RequestPDU(_) => make_initiate_resp_pdu(),

                    MMSpdu::confirmed_RequestPDU(pdu) => {
                        assert_eq!(pdu.list_of_modifiers, None);
                        assert_eq!(pdu.service, expected_req);
                        make_resp_pdu(pdu.invoke_id, resp.clone())
                    }

                    _ => panic!("unexpected PDU"),
                };

                in_tx.send(resp).await.unwrap();
            }
        });

        // Client
        let client = Client::start(channel).await.unwrap();

        assert!(client.is_connected());

        let result = client.request(req, None).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_resp);
    }

    #[tokio::test]
    async fn multi_request() {
        const NUM_REQS: u32 = 100;
        let reqs: Vec<ConfirmedServiceRequest> = (0..NUM_REQS).map(make_req).collect();

        // Channel
        let (out_tx, mut out_rx) = futures::channel::mpsc::channel(10);
        let (mut in_tx, in_rx) = futures::channel::mpsc::channel(10);
        let channel = (out_tx, in_rx);

        // Server
        tokio::spawn(async move {
            let mut resps: Vec<MMSpdu> = Vec::new();

            while let Some(pdu) = out_rx.next().await {
                match pdu {
                    MMSpdu::initiate_RequestPDU(_) => {
                        in_tx.send(make_initiate_resp_pdu()).await.unwrap();
                    }

                    MMSpdu::confirmed_RequestPDU(pdu) => {
                        // Validate request content and order
                        if let ConfirmedRequestPDU {
                            invoke_id: _,
                            list_of_modifiers: None,
                            service: ConfirmedServiceRequest::fileRead(FileReadRequest(Integer32(id))),
                        } = pdu
                        {
                            assert_eq!(id, resps.len() as i32);
                        } else {
                            panic!("unexpected request content");
                        }
                        resps.push(make_resp_pdu(pdu.invoke_id, make_resp(resps.len() as u32)));

                        // Sleep to simulate server processing time and add backpressure to the channel
                        tokio::time::sleep(Duration::from_millis(5)).await;

                        // Drop out once all requests have been received
                        if resps.len() >= NUM_REQS as usize {
                            break;
                        }
                    }

                    _ => panic!("unexpected PDU"),
                }
            }

            // Respond in random order
            let mut rng = StdRng::seed_from_u64(0x5EED);
            resps.shuffle(&mut rng);
            while let Some(pdu) = resps.pop() {
                in_tx.send(pdu).await.unwrap();
            }
        });

        // Client
        let client = Client::start(channel).await.unwrap();

        // Send all requests
        let resp_futures = reqs.iter().map(|pdu| client.request(pdu.clone(), None));

        // Await all responses concurrently
        let results = futures::future::join_all(resp_futures).await;

        assert!(results.iter().all(|result| result.is_ok()));

        let resps = results.into_iter().map(|result| result.unwrap()).collect::<Vec<_>>();

        // Ensure correct response mapping (despite response order reversal)
        assert_eq!(*resps.first().unwrap(), make_resp(0));
        assert_eq!(*resps.last().unwrap(), make_resp(NUM_REQS - 1));
    }

    #[tokio::test]
    async fn error_response() {
        let req = make_req(123);

        let expected_err = Error::ServiceError(make_err());

        // Channel
        let (out_tx, mut out_rx) = futures::channel::mpsc::channel(1);
        let (mut in_tx, in_rx) = futures::channel::mpsc::channel(1);
        let channel = (out_tx, in_rx);

        // Server
        tokio::spawn(async move {
            while let Some(pdu) = out_rx.next().await {
                let resp = match pdu {
                    MMSpdu::initiate_RequestPDU(_) => make_initiate_resp_pdu(),

                    MMSpdu::confirmed_RequestPDU(pdu) => make_err_pdu(pdu.invoke_id, make_err()),

                    _ => panic!("unexpected PDU"),
                };

                in_tx.send(resp).await.unwrap();
            }
        });

        // Client
        let client = Client::start(channel).await.unwrap();
        let result = client.request(req, None).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), expected_err.to_string());
    }

    #[tokio::test]
    async fn reject_request() {
        let req = make_req(123);

        // Channel
        let (out_tx, mut out_rx) = futures::channel::mpsc::channel(1);
        let (mut in_tx, in_rx) = futures::channel::mpsc::channel(1);
        let channel = (out_tx, in_rx);

        // Server
        tokio::spawn(async move {
            while let Some(pdu) = out_rx.next().await {
                let resp = match pdu {
                    MMSpdu::initiate_RequestPDU(_) => make_initiate_resp_pdu(),

                    MMSpdu::confirmed_RequestPDU(pdu) => make_reject_pdu(Some(pdu.invoke_id)),

                    _ => panic!("unexpected PDU"),
                };

                in_tx.send(resp).await.unwrap();
            }
        });

        // Client
        let client = Client::start(channel).await.unwrap();
        let result = client.request(req, None).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::BadRequest(_)));
    }

    #[tokio::test]
    async fn cancel_request() {
        // Channel
        let (out_tx, mut out_rx) = futures::channel::mpsc::channel(1);
        let (mut in_tx, in_rx) = futures::channel::mpsc::channel(1);
        let channel = (out_tx, in_rx);

        // Server
        tokio::spawn(async move {
            let mut test_case = 0;
            let mut current_session = None;

            while let Some(pdu) = out_rx.next().await {
                match pdu {
                    MMSpdu::initiate_RequestPDU(_) => {
                        in_tx.send(make_initiate_resp_pdu()).await.unwrap();
                    }

                    MMSpdu::confirmed_RequestPDU(ConfirmedRequestPDU { invoke_id, .. }) => {
                        current_session = Some(invoke_id.0);
                    }

                    MMSpdu::cancel_RequestPDU(CancelRequestPDU(invoke_id)) => {
                        assert_eq!(invoke_id.0, current_session.unwrap());

                        test_case += 1;

                        match test_case {
                            // Case 1: send Cancel-Response before Confirmed-Error (success)
                            1 => {
                                in_tx
                                    .send(MMSpdu::cancel_ResponsePDU(CancelResponsePDU(invoke_id.clone())))
                                    .await
                                    .unwrap();

                                in_tx.send(make_err_pdu(invoke_id.clone(), make_err())).await.unwrap();
                            }

                            // Case 2: send Confirmed-Error before Cancel-Response (success)
                            2 => {
                                in_tx.send(make_err_pdu(invoke_id.clone(), make_err())).await.unwrap();

                                in_tx
                                    .send(MMSpdu::cancel_ResponsePDU(CancelResponsePDU(invoke_id.clone())))
                                    .await
                                    .unwrap();
                            }

                            // Case 3: send Cancel-Error then Confirmed-Response (fail)
                            3 => {
                                in_tx
                                    .send(MMSpdu::cancel_ErrorPDU(CancelErrorPDU {
                                        original_invoke_id: invoke_id.clone(),
                                        service_error: make_err(),
                                    }))
                                    .await
                                    .unwrap();

                                in_tx
                                    .send(make_resp_pdu(invoke_id.clone(), make_resp(test_case)))
                                    .await
                                    .unwrap();
                            }

                            // Case 4: Confirmed-Response then a Cancel-Error (fail)
                            4 => {
                                in_tx
                                    .send(make_resp_pdu(invoke_id.clone(), make_resp(test_case)))
                                    .await
                                    .unwrap();

                                in_tx
                                    .send(MMSpdu::cancel_ErrorPDU(CancelErrorPDU {
                                        original_invoke_id: invoke_id.clone(),
                                        service_error: make_err(),
                                    }))
                                    .await
                                    .unwrap();
                            }

                            // Case 5: server sends Reject PDU (fail)
                            5 => {
                                in_tx.send(make_reject_pdu(Some(invoke_id))).await.unwrap();
                            }

                            _ => panic!("unexpected test case"),
                        }
                    }

                    _ => panic!("unexpected PDU"),
                }
            }
        });

        // Client
        let client = Client::start(channel).await.unwrap();

        // Case 1: cancellation succeeds, cancel confirmed first
        let pending = client.start_request(make_req(1), None).await.unwrap();
        let result = client.cancel_request(pending).await;
        assert!(result.is_ok());

        // Case 2: cancellation succeeds, request error first
        let pending = client.start_request(make_req(2), None).await.unwrap();
        let result = client.cancel_request(pending).await;
        assert!(result.is_ok());

        // Case 3: cancellation fails, cancel error first
        let pending = client.start_request(make_req(3), None).await.unwrap();
        let result = client.cancel_request(pending).await;
        assert!(matches!(result, Err(Error::Canceled)));

        // Case 4: cancellation fails, request response first
        let pending = client.start_request(make_req(4), None).await.unwrap();
        let result = client.cancel_request(pending).await;
        assert!(matches!(result, Err(Error::Canceled)));

        // Case 5: cancellation fails, server rejects message
        let pending = client.start_request(make_req(5), None).await.unwrap();
        let result = client.cancel_request(pending).await;
        assert!(matches!(result, Err(Error::BadRequest(_))));
    }

    #[tokio::test]
    async fn unconfirmed_handler() {
        // Channel
        let (out_tx, mut out_rx) = futures::channel::mpsc::channel(1);
        let (mut in_tx, in_rx) = futures::channel::mpsc::channel(1);
        let channel = (out_tx, in_rx);

        // Server
        tokio::spawn(async move {
            while let Some(pdu) = out_rx.next().await {
                match pdu {
                    MMSpdu::initiate_RequestPDU(_) => {
                        in_tx.send(make_initiate_resp_pdu()).await.unwrap();

                        // After initiate, send 3 Unconfirmed messages
                        in_tx.send(make_unconfirmed_pdu(1)).await.unwrap();
                        in_tx.send(make_unconfirmed_pdu(2)).await.unwrap();
                        in_tx.send(make_unconfirmed_pdu(3)).await.unwrap();
                    }

                    _ => panic!("unexpected PDU"),
                }
            }
        });

        // Client
        let client = Client::start(channel).await.unwrap();

        assert!(client.is_connected());

        let mut handler = client.handle_unconfirmed();

        assert_eq!(
            MMSpdu::unconfirmed_PDU(UnconfirmedPDU {
                service: handler.recv().await.unwrap()
            }),
            make_unconfirmed_pdu(1)
        );
        assert_eq!(
            MMSpdu::unconfirmed_PDU(UnconfirmedPDU {
                service: handler.recv().await.unwrap()
            }),
            make_unconfirmed_pdu(2)
        );
        assert_eq!(
            MMSpdu::unconfirmed_PDU(UnconfirmedPDU {
                service: handler.recv().await.unwrap()
            }),
            make_unconfirmed_pdu(3)
        );
    }

    #[tokio::test]
    async fn initiate_error() {
        // Channel
        let (out_tx, mut out_rx) = futures::channel::mpsc::channel(1);
        let (mut in_tx, in_rx) = futures::channel::mpsc::channel(1);
        let channel = (out_tx, in_rx);

        // Server
        tokio::spawn(async move {
            while let Some(pdu) = out_rx.next().await {
                let resp = match pdu {
                    MMSpdu::initiate_RequestPDU(_) => MMSpdu::initiate_ErrorPDU(InitiateErrorPDU(ServiceError {
                        error_class: ServiceErrorErrorClass::resource(4),
                        additional_code: None,
                        additional_description: None,
                        service_specific_info: None,
                    })),

                    _ => panic!("unexpected PDU"),
                };

                in_tx.send(resp).await.unwrap();
            }
        });

        // Client
        let result = Client::start(channel).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), Error::ConnectionClosed.to_string());
    }

    #[tokio::test]
    async fn initiate_fail() {
        // Channel
        let (out_tx, mut out_rx) = futures::channel::mpsc::channel(1);
        let (_in_tx, in_rx) = futures::channel::mpsc::channel(1);
        let channel = (out_tx, in_rx);

        out_rx.close();

        // Client
        let result = Client::start(channel).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), Error::ConnectionClosed.to_string());
    }

    #[tokio::test]
    async fn send_fail() {
        let req = make_req(123);

        // Channel
        let (out_tx, mut out_rx) = futures::channel::mpsc::channel(1);
        let (mut in_tx, in_rx) = futures::channel::mpsc::channel(1);
        let channel = (out_tx, in_rx);

        // Server
        tokio::spawn(async move {
            while let Some(pdu) = out_rx.next().await {
                match pdu {
                    MMSpdu::initiate_RequestPDU(_) => {
                        in_tx.send(make_initiate_resp_pdu()).await.unwrap();

                        // Close output channel after initiate
                        out_rx.close();
                    }

                    _ => panic!("unexpected PDU"),
                };
            }
        });

        // Client
        let client = Client::start(channel).await.unwrap();

        let result = client.request(req, None).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), Error::ConnectionClosed.to_string());
        assert!(!client.is_connected());
    }

    #[tokio::test]
    async fn receive_fail() {
        let req = make_req(123);

        // Channel
        let (out_tx, mut out_rx) = futures::channel::mpsc::channel(1);
        let (mut in_tx, in_rx) = futures::channel::mpsc::channel(1);
        let channel = (out_tx, in_rx);

        // Server
        tokio::spawn(async move {
            while let Some(pdu) = out_rx.next().await {
                match pdu {
                    MMSpdu::initiate_RequestPDU(_) => {
                        in_tx.send(make_initiate_resp_pdu()).await.unwrap();

                        // Close input channel after initiate
                        in_tx.close().await.unwrap();
                    }

                    _ => panic!("unexpected PDU"),
                };
            }
        });

        // Client
        let client = Client::start(channel).await.unwrap();

        let result = client.request(req, None).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), Error::ConnectionClosed.to_string());
        assert!(!client.is_connected());
    }

    #[tokio::test]
    async fn request_timeout() {
        let req = make_req(123);

        // Channel
        let (out_tx, mut out_rx) = futures::channel::mpsc::channel(1);
        let (mut in_tx, in_rx) = futures::channel::mpsc::channel(1);
        let channel = (out_tx, in_rx);

        // Server
        tokio::spawn(async move {
            while let Some(pdu) = out_rx.next().await {
                match pdu {
                    MMSpdu::initiate_RequestPDU(_) => in_tx.send(make_initiate_resp_pdu()).await.unwrap(),

                    _ => {
                        // ignore other requests
                    }
                };
            }
        });

        // Client
        let client = Client::start(channel).await.unwrap();

        // Timeout first message due to response not received
        let result = client
            .request_with_timeout(req.clone(), None, Duration::from_millis(100))
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), Error::Timeout.to_string());

        // Timeout second message due to send channel full
        let result = client.request_with_timeout(req, None, Duration::from_millis(100)).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), Error::Timeout.to_string());
    }

    // TCP connection
    mod tcp {
        use super::*;
        use crate::protocol::*;

        struct Server {
            pub addr: std::net::SocketAddr,
            task: Option<tokio::task::JoinHandle<()>>,
        }

        impl Server {
            // Create a trivial MMS test server
            async fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
                let _ = env_logger::builder()
                    .filter_level(log::LevelFilter::Trace)
                    .is_test(true)
                    .try_init();

                // Bind a TCP server to localhost on a free ephemeral port
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                let addr = listener.local_addr()?;

                // Run the server on a dedicated async task
                let task = tokio::spawn(async move {
                    while let Ok((socket, _)) = listener.accept().await {
                        tokio::spawn(async move {
                            let mut params = protocol::ProtocolParams::default();

                            let framed = tokio_util::codec::Framed::new(socket, tpkt::TpktCodec);

                            let connection = transport::accept(framed, params.transport.clone())
                                .await
                                .expect("COTP connection");

                            let (mut sink, mut stream) = connection.split();

                            while let Some(Ok(frame)) = stream.next().await {
                                let pdu = decode(frame, &mut params).expect("decode");

                                let resp = match pdu {
                                    MMSpdu::initiate_RequestPDU(_) => make_initiate_resp_pdu(),

                                    MMSpdu::confirmed_RequestPDU(req) => {
                                        MMSpdu::confirmed_ErrorPDU(ConfirmedErrorPDU {
                                            invoke_id: req.invoke_id,
                                            modifier_position: None,
                                            service_error: ServiceError {
                                                error_class: ServiceErrorErrorClass::resource(4),
                                                additional_code: None,
                                                additional_description: None,
                                                service_specific_info: None,
                                            },
                                        })
                                    }

                                    _ => panic!("unexpected PDU"),
                                };

                                let frame = encode(&resp, &params).expect("encode");

                                sink.send(frame).await.unwrap();
                            }
                        });
                    }
                });

                Ok(Self { addr, task: Some(task) })
            }
        }

        impl Drop for Server {
            fn drop(&mut self) {
                if let Some(task) = self.task.take() {
                    task.abort();
                }
            }
        }

        #[tokio::test]
        async fn connect_and_request() {
            let server = Server::new().await.expect("server binds to ephemeral port");

            let client = Client::builder()
                .timeout_after(Duration::from_secs(1))
                .connect(server.addr.ip().to_string(), server.addr.port())
                .await
                .unwrap_or_else(|_| panic!("client TCP connect to {}", server.addr));

            assert!(client.is_connected());

            let result = client.status(false).await;

            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err().to_string(),
                Error::ServiceError(ServiceError {
                    error_class: ServiceErrorErrorClass::resource(4),
                    additional_code: None,
                    additional_description: None,
                    service_specific_info: None,
                })
                .to_string()
            );
        }

        #[tokio::test]
        async fn connect_error() {
            let result = Client::builder()
                .timeout_after(Duration::from_secs(1))
                .connect("foo", 9999)
                .await
                .unwrap_err();

            assert!(matches!(result, Error::Io(_)));
        }
    }
}
