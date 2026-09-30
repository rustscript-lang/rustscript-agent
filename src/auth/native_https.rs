//! Bounded native HTTPS transport for the injected OAuth host.
//!
//! DNS resolution uses Tokio's bounded blocking pool. Aborting a request stops
//! its async work, but cannot preempt an OS resolver call already running;
//! the pool is limited to two threads and request admission to 32 in flight.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, mpsc};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::{Method, Request, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::runtime::Runtime;
use tokio::sync::Semaphore;
use tokio_rustls::TlsConnector;

use crate::auth::oauth::{
    BoundedHttpsTransport, OAuthError, OAuthIoContext, PreparedHttpsRequest, RawHttpsResponse,
};

const MAX_HEADERS: usize = 32;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_ACTIVE_REQUESTS: usize = 32;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
static RUNTIME: OnceLock<Option<Runtime>> = OnceLock::new();
static REQUESTS: OnceLock<Arc<Semaphore>> = OnceLock::new();

fn failed() -> OAuthError {
    OAuthError::Transport {
        message: "native_https_failed".into(),
    }
}

fn busy() -> OAuthError {
    OAuthError::Transport {
        message: "native_https_busy".into(),
    }
}

/// Explicitly injected HTTPS transport; it never uses proxy settings or follows redirects.
pub struct NativeHttpsTransport {
    tls: Arc<rustls::ClientConfig>,
}

impl NativeHttpsTransport {
    pub fn new() -> Self {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        Self::from_roots(roots)
    }

    fn from_roots(roots: rustls::RootCertStore) -> Self {
        Self {
            tls: Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            ),
        }
    }

    #[cfg(test)]
    fn with_roots(roots: rustls::RootCertStore) -> Self {
        Self::from_roots(roots)
    }
}

impl Default for NativeHttpsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl BoundedHttpsTransport for NativeHttpsTransport {
    fn send(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        context.check()?;
        if request.body.len() > context.max_request_body_bytes() {
            return Err(OAuthError::RequestTooLarge {
                max_bytes: context.max_request_body_bytes(),
            });
        }
        let url = url::Url::parse(&request.url).map_err(|_| failed())?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(failed());
        }
        let host = url.host_str().ok_or_else(failed)?.to_owned();
        let port = url.port_or_known_default().ok_or_else(failed)?;
        let name = ServerName::try_from(host.clone()).map_err(|_| failed())?;
        let uri: Uri = request.url.parse().map_err(|_| failed())?;
        let authority = uri.authority().ok_or_else(failed)?.as_str().to_owned();
        if uri.scheme_str() != Some("https") || authority.contains('@') {
            return Err(failed());
        }
        let method = Method::from_bytes(request.method.as_bytes()).map_err(|_| failed())?;
        if request.headers.len().saturating_add(1) > MAX_HEADERS {
            return Err(failed());
        }
        let mut header_bytes = hyper::header::HOST
            .as_str()
            .len()
            .saturating_add(authority.len())
            .saturating_add(4);
        for (key, value) in &request.headers {
            if key.eq_ignore_ascii_case("host") {
                return Err(failed());
            }
            header_bytes = header_bytes
                .saturating_add(key.len())
                .saturating_add(value.len())
                .saturating_add(4);
            if header_bytes > MAX_HEADER_BYTES {
                return Err(failed());
            }
        }
        let mut builder = Request::builder()
            .method(method)
            .uri(uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"))
            .header(hyper::header::HOST, authority);
        for (key, value) in &request.headers {
            builder = builder.header(key.as_str(), value.as_str());
        }
        let request = builder
            .body(Full::new(Bytes::from(request.body.clone())))
            .map_err(|_| failed())?;
        let _permit =
            Arc::clone(REQUESTS.get_or_init(|| Arc::new(Semaphore::new(MAX_ACTIVE_REQUESTS))))
                .try_acquire_owned()
                .map_err(|_| busy())?;
        let runtime = RUNTIME
            .get_or_init(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .max_blocking_threads(2)
                    .enable_all()
                    .build()
                    .ok()
            })
            .as_ref()
            .ok_or_else(failed)?;
        let tls = Arc::clone(&self.tls);
        let owned_context = context.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        let task = runtime.spawn(async move {
            let result = tokio::time::timeout_at(owned_context.deadline().into(), async {
                let addresses = tokio::net::lookup_host((host.as_str(), port)).await.map_err(|_| failed())?;
                owned_context.check()?;
                let mut connected = None;
                for address in addresses {
                    owned_context.check()?;
                    if let Ok(stream) = tokio::net::TcpStream::connect(address).await {
                        connected = Some(stream);
                        break;
                    }
                }
                let stream = connected.ok_or_else(failed)?;
                owned_context.check()?;
                let stream = TlsConnector::from(tls).connect(name, stream).await.map_err(|_| failed())?;
                owned_context.check()?;
                let (mut sender, connection) = http1::Builder::new().max_headers(MAX_HEADERS).max_buf_size(MAX_HEADER_BYTES).handshake(TokioIo::new(stream)).await.map_err(|_| failed())?;
                owned_context.check()?;
                tokio::pin!(connection);
                tokio::select! {
                    result = async {
                        let response = sender.send_request(request).await.map_err(|_| failed())?;
                        owned_context.check()?;
                        let mut headers = BTreeMap::new();
                        let mut size = 0usize;
                        for (name, value) in response.headers() {
                            size = size.saturating_add(name.as_str().len()).saturating_add(value.as_bytes().len());
                            if size > MAX_HEADER_BYTES { return Err(failed()); }
                            headers.insert(name.to_string(), value.to_str().map_err(|_| failed())?.to_string());
                        }
                        let status = response.status().as_u16();
                        let mut incoming = response.into_body();
                        let mut body = Vec::new();
                        while let Some(frame) = incoming.frame().await {
                            owned_context.check()?;
                            let frame = frame.map_err(|_| failed())?;
                            if let Some(chunk) = frame.data_ref() {
                                if chunk.len() > owned_context.max_response_body_bytes().saturating_sub(body.len()) {
                                    return Err(OAuthError::ResponseTooLarge { max_bytes: owned_context.max_response_body_bytes() });
                                }
                                body.extend_from_slice(chunk);
                            }
                        }
                        owned_context.check()?;
                        Ok(RawHttpsResponse { status, headers, body })
                    } => result,
                    _ = &mut connection => Err(failed()),
                }
            }).await.unwrap_or(Err(OAuthError::DeadlineExceeded));
            let _ = tx.send(result);
        });
        loop {
            let remaining = match context.remaining() {
                Ok(remaining) => remaining,
                Err(error) => {
                    task.abort();
                    return Err(error);
                }
            };
            match rx.recv_timeout(remaining.min(POLL_INTERVAL)) {
                Ok(result) => {
                    context.check()?;
                    return result;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    context.check()?;
                    return Err(failed());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use futures_util::stream;
    use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
    use hyper::body::Frame;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use rustls::pki_types::PrivatePkcs8KeyDer;

    use super::*;
    use crate::auth::oauth::{OAuthCancel, OAuthClock};

    struct WallClock;
    impl OAuthClock for WallClock {
        fn now(&self) -> Instant {
            Instant::now()
        }
        fn unix_ms(&self) -> u64 {
            0
        }
    }
    struct Cancel(AtomicBool);
    impl OAuthCancel for Cancel {
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
    }
    fn context(duration: Duration) -> (OAuthIoContext, Arc<Cancel>) {
        let cancel = Arc::new(Cancel(AtomicBool::new(false)));
        (
            OAuthIoContext::new(
                Instant::now() + duration,
                Arc::new(WallClock),
                cancel.clone(),
            ),
            cancel,
        )
    }
    fn request(url: String) -> PreparedHttpsRequest {
        PreparedHttpsRequest {
            method: "POST".into(),
            url,
            headers: BTreeMap::from([("x-public".into(), "visible".into())]),
            body: "payload".into(),
        }
    }
    type ObservedRequest = (String, String, String);
    type BasicTlsServer = (
        String,
        rustls::RootCertStore,
        mpsc::Receiver<ObservedRequest>,
        std::thread::JoinHandle<()>,
    );

    fn server() -> BasicTlsServer {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certified.cert.der().clone()).unwrap();
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!(
            "https://localhost:{}/v1/token?flag=ok",
            listener.local_addr().unwrap().port()
        );
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let accept_deadline = Instant::now() + Duration::from_secs(2);
                let tcp = loop {
                    match listener.accept() {
                        Ok((tcp, _)) => break tcp,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= accept_deadline {
                                return;
                            }
                            tokio::time::sleep(Duration::from_millis(2)).await;
                        }
                        Err(_) => return,
                    }
                };
                if tcp.set_nonblocking(true).is_err() {
                    return;
                }
                let Ok(stream) = tokio::net::TcpStream::from_std(tcp) else {
                    return;
                };
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
                let Ok(Ok(tls)) =
                    tokio::time::timeout(Duration::from_secs(2), acceptor.accept(stream)).await
                else {
                    return;
                };
                let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let _ = tx.send((
                        req.uri().to_string(),
                        req.headers()["x-public"].to_str().unwrap().to_string(),
                        req.headers()["host"].to_str().unwrap().to_string(),
                    ));
                    async {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                    }
                });
                let _ = tokio::time::timeout(
                    Duration::from_secs(2),
                    http1::Builder::new().serve_connection(TokioIo::new(tls), service),
                )
                .await;
            });
        });
        (url, roots, rx, thread)
    }

    enum Reply {
        Fixed {
            status: u16,
            headers: Vec<(String, String)>,
            body: Vec<u8>,
        },
        ChunkedOversize,
        StallHandshake(Duration),
        StallResponse(Duration),
    }

    enum ServerEvent {
        TcpAccepted,
        Request {
            path: String,
            public_header: String,
            host: String,
            authorization: String,
        },
    }

    fn scripted_server(
        reply: Reply,
    ) -> (
        String,
        rustls::RootCertStore,
        mpsc::Receiver<ServerEvent>,
        std::thread::JoinHandle<()>,
    ) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certified.cert.der().clone()).unwrap();
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!(
            "https://localhost:{}/test",
            listener.local_addr().unwrap().port()
        );
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let accept_deadline = Instant::now() + Duration::from_secs(2);
                let tcp = loop {
                    match listener.accept() {
                        Ok((tcp, _)) => break tcp,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= accept_deadline {
                                return;
                            }
                            tokio::time::sleep(Duration::from_millis(2)).await;
                        }
                        Err(_) => return,
                    }
                };
                let _ = tx.send(ServerEvent::TcpAccepted);
                if let Reply::StallHandshake(duration) = &reply {
                    tokio::time::sleep(*duration).await;
                    return;
                }
                if tcp.set_nonblocking(true).is_err() {
                    return;
                }
                let Ok(stream) = tokio::net::TcpStream::from_std(tcp) else {
                    return;
                };
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
                let Ok(Ok(tls)) =
                    tokio::time::timeout(Duration::from_secs(2), acceptor.accept(stream)).await
                else {
                    return;
                };
                let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let _ = tx.send(ServerEvent::Request {
                        path: req.uri().to_string(),
                        public_header: req.headers()["x-public"]
                            .to_str()
                            .unwrap_or_default()
                            .to_owned(),
                        host: req.headers()["host"]
                            .to_str()
                            .unwrap_or_default()
                            .to_owned(),
                        authorization: req
                            .headers()
                            .get("authorization")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_owned(),
                    });
                    let reply = match &reply {
                        Reply::Fixed {
                            status,
                            headers,
                            body,
                        } => Reply::Fixed {
                            status: *status,
                            headers: headers.clone(),
                            body: body.clone(),
                        },
                        Reply::ChunkedOversize => Reply::ChunkedOversize,
                        Reply::StallResponse(duration) => Reply::StallResponse(*duration),
                        Reply::StallHandshake(_) => unreachable!(),
                    };
                    async move {
                        let response: Response<BoxBody<Bytes, Infallible>> = match reply {
                            Reply::Fixed {
                                status,
                                headers,
                                body,
                            } => {
                                let mut builder = Response::builder().status(status);
                                for (name, value) in headers {
                                    builder = builder.header(name, value);
                                }
                                builder.body(Full::new(Bytes::from(body)).boxed()).unwrap()
                            }
                            Reply::ChunkedOversize => {
                                let chunks =
                                    vec![
                                        Ok::<_, Infallible>(Frame::data(Bytes::from(
                                            vec![b'a'; 40 * 1024],
                                        ))),
                                        Ok::<_, Infallible>(Frame::data(Bytes::from(
                                            vec![b'b'; 40 * 1024],
                                        ))),
                                    ];
                                Response::new(StreamBody::new(stream::iter(chunks)).boxed())
                            }
                            Reply::StallResponse(duration) => {
                                tokio::time::sleep(duration).await;
                                Response::new(Full::new(Bytes::from_static(b"ok")).boxed())
                            }
                            Reply::StallHandshake(_) => unreachable!(),
                        };
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = tokio::time::timeout(
                    Duration::from_secs(4),
                    http1::Builder::new().serve_connection(TokioIo::new(tls), service),
                )
                .await;
            });
        });
        (url, roots, rx, thread)
    }

    fn stalled_server(
        stall: Duration,
    ) -> (
        String,
        rustls::RootCertStore,
        mpsc::Receiver<()>,
        std::thread::JoinHandle<()>,
    ) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certified.cert.der().clone()).unwrap();
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!(
            "https://localhost:{}/busy",
            listener.local_addr().unwrap().port()
        );
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
                let accept_deadline = Instant::now() + Duration::from_secs(2);
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    let remaining = accept_deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    let Ok(Ok((tcp, _))) = tokio::time::timeout(remaining, listener.accept()).await
                    else {
                        break;
                    };
                    let acceptor = acceptor.clone();
                    let tx = tx.clone();
                    connections.spawn(async move {
                        let Ok(Ok(tls)) =
                            tokio::time::timeout(Duration::from_secs(2), acceptor.accept(tcp))
                                .await
                        else {
                            return;
                        };
                        let service = service_fn(move |_req: Request<hyper::body::Incoming>| {
                            let tx = tx.clone();
                            async move {
                                let _ = tx.send(());
                                tokio::time::sleep(stall).await;
                                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                                    b"ok",
                                ))))
                            }
                        });
                        let _ = tokio::time::timeout(
                            Duration::from_secs(4),
                            http1::Builder::new().serve_connection(TokioIo::new(tls), service),
                        )
                        .await;
                    });
                }
                while connections.join_next().await.is_some() {}
            });
        });
        (url, roots, rx, thread)
    }

    #[test]
    fn plaintext_http_url_is_refused_before_connecting() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(300);
            loop {
                match listener.accept() {
                    Ok((_, _)) => {
                        let _ = accepted_tx.send(true);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            let _ = accepted_tx.send(false);
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => {
                        let _ = accepted_tx.send(true);
                        return;
                    }
                }
            }
        });
        let (io_context, _) = context(Duration::from_secs(1));
        let error = NativeHttpsTransport::new()
            .send(&request(format!("http://{address}/plaintext")), &io_context)
            .unwrap_err();
        assert_eq!(error.code(), "transport_error");
        assert!(!accepted_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        server.join().unwrap();
    }

    #[test]
    fn refuses_plaintext_userinfo_and_fragment_without_network() {
        let (context, _) = context(Duration::from_secs(1));
        let transport = NativeHttpsTransport::new();
        for url in [
            "http://localhost/private",
            "https://user@localhost/private",
            "https://localhost/private#fragment",
        ] {
            assert_eq!(
                transport
                    .send(&request(url.into()), &context)
                    .unwrap_err()
                    .code(),
                "transport_error"
            );
        }
    }

    #[test]
    fn refuses_empty_userinfo_before_connecting() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(300);
            loop {
                match listener.accept() {
                    Ok((_, _)) => {
                        let _ = accepted_tx.send(true);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            let _ = accepted_tx.send(false);
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => {
                        let _ = accepted_tx.send(true);
                        return;
                    }
                }
            }
        });
        let (io_context, _) = context(Duration::from_secs(1));
        let error = NativeHttpsTransport::new()
            .send(&request(format!("https://@{address}/private")), &io_context)
            .unwrap_err();
        assert_eq!(error.code(), "transport_error");
        assert!(!accepted_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        server.join().unwrap();
    }

    #[test]
    fn refuses_header_authority_override_before_connecting() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match listener.accept() {
                    Ok((_, _)) => {
                        let _ = accepted_tx.send(true);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            let _ = accepted_tx.send(false);
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => {
                        let _ = accepted_tx.send(true);
                        return;
                    }
                }
            }
        });
        let (context, _) = context(Duration::from_secs(1));
        let mut injected = request(format!("https://{address}/private"));
        for name in ["Host", "host", "HoSt"] {
            injected
                .headers
                .insert(name.into(), "elsewhere.invalid".into());
            let error = NativeHttpsTransport::new()
                .send(&injected, &context)
                .unwrap_err();
            assert_eq!(error.code(), "transport_error");
            assert!(!error.to_string().contains("elsewhere.invalid"));
            injected.headers.remove(name);
        }
        assert!(!accepted_rx.recv_timeout(Duration::from_secs(3)).unwrap());
        server.join().unwrap();
    }

    #[test]
    fn loopback_tls_preserves_path_query_authority_and_injected_headers() {
        let (url, roots, events, server) = scripted_server(Reply::Fixed {
            status: 200,
            headers: Vec::new(),
            body: b"ok".to_vec(),
        });
        let url = url.replace("/test", "/v1/token?flag=a%2Fb&keep=%25");
        let authority = url
            .split_once("//")
            .unwrap()
            .1
            .split('/')
            .next()
            .unwrap()
            .to_owned();
        let transport = NativeHttpsTransport::with_roots(roots);
        let (io_context, _) = context(Duration::from_secs(3));
        let mut prepared = request(url);
        prepared.headers.insert(
            "authorization".into(),
            "Bearer test-credential-marker".into(),
        );
        let response = transport.send(&prepared, &io_context).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert!(matches!(
            events.recv_timeout(Duration::from_secs(2)).unwrap(),
            ServerEvent::TcpAccepted
        ));
        let ServerEvent::Request {
            path,
            public_header,
            host,
            authorization,
        } = events.recv_timeout(Duration::from_secs(2)).unwrap()
        else {
            panic!("the TLS server did not receive an HTTP request");
        };
        assert_eq!(path, "/v1/token?flag=a%2Fb&keep=%25");
        assert_eq!(public_header, "visible");
        assert_eq!(host, authority);
        assert_eq!(authorization, "Bearer test-credential-marker");
        server.join().unwrap();
    }

    #[test]
    fn rejects_oversized_response_headers_without_disclosing_values() {
        let secret_marker = "header-secret-marker";
        let value = format!("{}{}", "a".repeat(MAX_HEADER_BYTES), secret_marker);
        let (url, roots, _events, server) = scripted_server(Reply::Fixed {
            status: 200,
            headers: vec![("x-large".into(), value)],
            body: b"ok".to_vec(),
        });
        let transport = NativeHttpsTransport::with_roots(roots);
        let (io_context, _) = context(Duration::from_secs(3));
        let error = transport.send(&request(url), &io_context).unwrap_err();
        assert_eq!(error.code(), "transport_error");
        assert!(!error.to_string().contains(secret_marker));
        server.join().unwrap();
    }
    #[test]
    fn rejects_untrusted_loopback_certificate_and_redacts_url() {
        let marker = "query-secret-marker";
        let (url, _roots, events, server) = scripted_server(Reply::Fixed {
            status: 200,
            headers: Vec::new(),
            body: b"ok".to_vec(),
        });
        let url = format!("{url}?secret={marker}");
        let (io_context, _) = context(Duration::from_secs(3));
        let error = NativeHttpsTransport::new()
            .send(&request(url), &io_context)
            .unwrap_err();
        assert_eq!(error.code(), "transport_error");
        assert!(!error.to_string().contains(marker));
        assert!(matches!(
            events.recv_timeout(Duration::from_secs(1)).unwrap(),
            ServerEvent::TcpAccepted
        ));
        server.join().unwrap();
        assert!(matches!(
            events.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn rejects_loopback_certificate_hostname_mismatch() {
        let (url, roots, events, server) = scripted_server(Reply::Fixed {
            status: 200,
            headers: Vec::new(),
            body: b"ok".to_vec(),
        });
        let url = url.replacen("localhost", "127.0.0.1", 1);
        let (io_context, _) = context(Duration::from_secs(3));
        let error = NativeHttpsTransport::with_roots(roots)
            .send(&request(url), &io_context)
            .unwrap_err();
        assert_eq!(error.code(), "transport_error");
        assert!(matches!(
            events.recv_timeout(Duration::from_secs(1)).unwrap(),
            ServerEvent::TcpAccepted
        ));
        server.join().unwrap();
        assert!(matches!(
            events.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn returns_redirect_without_connecting_to_location() {
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let redirect_url = format!("http://{}/redirect", destination.local_addr().unwrap());
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let destination_server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(500);
            loop {
                match destination.accept() {
                    Ok((_, _)) => {
                        let _ = accepted_tx.send(true);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            let _ = accepted_tx.send(false);
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => {
                        let _ = accepted_tx.send(true);
                        return;
                    }
                }
            }
        });
        let (url, roots, _events, server) = scripted_server(Reply::Fixed {
            status: 302,
            headers: vec![("location".into(), redirect_url)],
            body: b"redirect".to_vec(),
        });
        let transport = NativeHttpsTransport::with_roots(roots);
        let (io_context, _) = context(Duration::from_secs(3));
        let response = transport.send(&request(url), &io_context).unwrap();
        assert_eq!(response.status, 302);
        server.join().unwrap();
        assert!(!accepted_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        destination_server.join().unwrap();
    }

    #[test]
    fn rejects_oversized_chunked_body_without_content_length() {
        let (url, roots, _events, server) = scripted_server(Reply::ChunkedOversize);
        let transport = NativeHttpsTransport::with_roots(roots);
        let (io_context, _) = context(Duration::from_secs(3));
        let error = transport.send(&request(url), &io_context).unwrap_err();
        assert_eq!(error.code(), "response_too_large");
        server.join().unwrap();
    }

    #[test]
    fn rejects_excessive_response_header_count() {
        let headers = (0..=MAX_HEADERS)
            .map(|index| (format!("x-test-{index}"), "value".to_owned()))
            .collect();
        let (url, roots, _events, server) = scripted_server(Reply::Fixed {
            status: 200,
            headers,
            body: b"ok".to_vec(),
        });
        let transport = NativeHttpsTransport::with_roots(roots);
        let (io_context, _) = context(Duration::from_secs(3));
        let error = transport.send(&request(url), &io_context).unwrap_err();
        assert_eq!(error.code(), "transport_error");
        server.join().unwrap();
    }

    #[test]
    fn request_body_over_limit_is_refused_before_connecting() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(300);
            loop {
                match listener.accept() {
                    Ok((_, _)) => {
                        let _ = accepted_tx.send(true);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            let _ = accepted_tx.send(false);
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => {
                        let _ = accepted_tx.send(true);
                        return;
                    }
                }
            }
        });
        let (io_context, _) = context(Duration::from_secs(1));
        let mut oversized = request(format!("https://{address}/body"));
        oversized.body = "x".repeat(io_context.max_request_body_bytes() + 1);
        let error = NativeHttpsTransport::new()
            .send(&oversized, &io_context)
            .unwrap_err();
        assert_eq!(error.code(), "request_too_large");
        assert!(!accepted_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        server.join().unwrap();
    }

    #[test]
    fn stalled_tls_handshake_obeys_absolute_deadline() {
        let (url, roots, events, server) =
            scripted_server(Reply::StallHandshake(Duration::from_millis(600)));
        let transport = NativeHttpsTransport::with_roots(roots);
        let (io_context, _) = context(Duration::from_millis(150));
        let started = Instant::now();
        let sender = std::thread::spawn(move || transport.send(&request(url), &io_context));
        assert!(matches!(
            events.recv_timeout(Duration::from_secs(1)).unwrap(),
            ServerEvent::TcpAccepted
        ));
        let error = sender.join().unwrap().unwrap_err();
        assert_eq!(error.code(), "deadline_exceeded");
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }

    #[test]
    fn stalled_response_obeys_absolute_deadline() {
        let (url, roots, events, server) =
            scripted_server(Reply::StallResponse(Duration::from_millis(600)));
        let transport = NativeHttpsTransport::with_roots(roots);
        let (io_context, _) = context(Duration::from_millis(150));
        let started = Instant::now();
        let sender = std::thread::spawn(move || transport.send(&request(url), &io_context));
        assert!(matches!(
            events.recv_timeout(Duration::from_secs(1)).unwrap(),
            ServerEvent::TcpAccepted
        ));
        assert!(matches!(
            events.recv_timeout(Duration::from_secs(1)).unwrap(),
            ServerEvent::Request { .. }
        ));
        let error = sender.join().unwrap().unwrap_err();
        assert_eq!(error.code(), "deadline_exceeded");
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }

    #[test]
    fn cancellation_after_tcp_accept_aborts_in_flight_tls() {
        let (url, roots, events, server) =
            scripted_server(Reply::StallHandshake(Duration::from_millis(600)));
        let transport = NativeHttpsTransport::with_roots(roots);
        let (io_context, cancel) = context(Duration::from_secs(3));
        let sender = std::thread::spawn(move || transport.send(&request(url), &io_context));
        assert!(matches!(
            events.recv_timeout(Duration::from_secs(1)).unwrap(),
            ServerEvent::TcpAccepted
        ));
        cancel.0.store(true, Ordering::Release);
        let error = sender.join().unwrap().unwrap_err();
        assert_eq!(error.code(), "cancelled");
        server.join().unwrap();
    }

    #[test]
    fn synchronous_send_works_inside_an_entered_tokio_runtime() {
        let (url, roots, observed, server) = server();
        let expected_authority = url
            .split_once("//")
            .unwrap()
            .1
            .split('/')
            .next()
            .unwrap()
            .to_owned();
        let transport = NativeHttpsTransport::with_roots(roots);
        let caller = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let (io_context, _) = context(Duration::from_secs(3));
                transport.send(&request(url), &io_context)
            })
        });
        assert_eq!(caller.join().unwrap().unwrap().status, 200);
        assert_eq!(
            observed.recv_timeout(Duration::from_secs(2)).unwrap(),
            (
                "/v1/token?flag=ok".into(),
                "visible".into(),
                expected_authority,
            )
        );
        server.join().unwrap();
    }

    #[test]
    fn generated_host_counts_toward_outgoing_header_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(300);
            loop {
                match listener.accept() {
                    Ok((_, _)) => {
                        let _ = accepted_tx.send(true);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            let _ = accepted_tx.send(false);
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => {
                        let _ = accepted_tx.send(true);
                        return;
                    }
                }
            }
        });
        let (io_context, _) = context(Duration::from_secs(1));
        let mut over_headered = request(format!("https://{address}/headers"));
        over_headered.headers.clear();
        for index in 0..MAX_HEADERS {
            over_headered
                .headers
                .insert(format!("x-test-{index}"), "value".into());
        }
        let error = NativeHttpsTransport::new()
            .send(&over_headered, &io_context)
            .unwrap_err();
        assert_eq!(error.code(), "transport_error");
        assert!(!accepted_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        server.join().unwrap();
    }

    #[test]
    fn outgoing_header_bytes_include_generated_host() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(300);
            loop {
                match listener.accept() {
                    Ok((_, _)) => {
                        let _ = accepted_tx.send(true);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            let _ = accepted_tx.send(false);
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => {
                        let _ = accepted_tx.send(true);
                        return;
                    }
                }
            }
        });
        let (io_context, _) = context(Duration::from_secs(1));
        let mut over_sized = request(format!("https://{address}/headers"));
        over_sized.headers.clear();
        over_sized
            .headers
            .insert("x".into(), "v".repeat(MAX_HEADER_BYTES - 1));
        let error = NativeHttpsTransport::new()
            .send(&over_sized, &io_context)
            .unwrap_err();
        assert_eq!(error.code(), "transport_error");
        assert!(!accepted_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        server.join().unwrap();
    }

    #[test]
    fn caps_concurrent_tls_requests_and_releases_admission_on_cancel() {
        const ACTIVE: usize = 32;
        let stall = Duration::from_secs(1);
        let (url, roots, received, server) = stalled_server(stall);
        let transport = Arc::new(NativeHttpsTransport::with_roots(roots));
        let start = Arc::new(Barrier::new(ACTIVE + 1));
        let mut clients = Vec::with_capacity(ACTIVE);
        let mut cancellations = Vec::with_capacity(ACTIVE);
        for _ in 0..ACTIVE {
            let transport = Arc::clone(&transport);
            let start = Arc::clone(&start);
            let url = url.clone();
            let (client_context, cancel) = context(Duration::from_secs(6));
            cancellations.push(cancel);
            clients.push(std::thread::spawn(move || {
                start.wait();
                transport.send(&request(url), &client_context)
            }));
        }
        start.wait();
        for _ in 0..ACTIVE {
            received.recv_timeout(Duration::from_secs(5)).unwrap();
        }

        let (overflow_context, _) = context(Duration::from_secs(6));
        let overflow_started = Instant::now();
        let overflow = transport
            .send(&request(url.clone()), &overflow_context)
            .unwrap_err();
        assert!(overflow_started.elapsed() < Duration::from_millis(250));
        assert_eq!(overflow.to_string(), "transport error: native_https_busy");
        assert!(!overflow.to_string().contains("?secret"));

        cancellations[0].0.store(true, Ordering::Release);
        assert_eq!(
            clients.remove(0).join().unwrap().unwrap_err().code(),
            "cancelled"
        );
        let replacement_transport = Arc::clone(&transport);
        let replacement_url = url.clone();
        let replacement = std::thread::spawn(move || {
            let (replacement_context, _) = context(Duration::from_secs(6));
            replacement_transport.send(&request(replacement_url), &replacement_context)
        });
        received.recv_timeout(Duration::from_secs(3)).unwrap();

        let (overflow_context, _) = context(Duration::from_secs(6));
        let overflow_started = Instant::now();
        let overflow = transport
            .send(&request(url.clone()), &overflow_context)
            .unwrap_err();
        assert!(overflow_started.elapsed() < Duration::from_millis(250));
        assert_eq!(overflow.to_string(), "transport error: native_https_busy");

        assert_eq!(replacement.join().unwrap().unwrap().status, 200);
        for client in clients {
            assert_eq!(client.join().unwrap().unwrap().status, 200);
        }

        let (release_context, _) = context(Duration::from_secs(2));
        assert_eq!(
            transport
                .send(&request(url), &release_context)
                .unwrap()
                .status,
            200
        );
        server.join().unwrap();
    }
}
