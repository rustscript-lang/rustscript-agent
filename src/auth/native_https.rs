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
    #[cfg(unix)]
    use std::os::fd::{AsRawFd, FromRawFd};
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

    #[cfg(unix)]
    const DEVICE_USER_CODE: &str = "PUBLIC-CODE-7QK";
    #[cfg(unix)]
    const DEVICE_START_PATH: &str = "/api/accounts/deviceauth/usercode";
    #[cfg(unix)]
    const DEVICE_POLL_PATH: &str = "/api/accounts/deviceauth/token";
    #[cfg(unix)]
    const DEVICE_TOKEN_PATH: &str = "/oauth/token";
    #[cfg(unix)]
    const DEVICE_CLIENT_ID: &str = "synthetic-public-client";

    #[cfg(unix)]
    const COMMANDS_SOURCES: &[(&str, &str)] = &[
        (
            "rss/auth/commands.rss",
            include_str!("../../rss/auth/commands.rss"),
        ),
        (
            "rss/config/selection.rss",
            include_str!("../../rss/config/selection.rss"),
        ),
        (
            "rss/auth/login.rss",
            include_str!("../../rss/auth/login.rss"),
        ),
        (
            "rss/auth/codex_device.rss",
            include_str!("../../rss/auth/codex_device.rss"),
        ),
        (
            "rss/auth/types.rss",
            include_str!("../../rss/auth/types.rss"),
        ),
    ];

    #[cfg(unix)]
    #[derive(Clone)]
    struct DeviceFlowSecrets {
        device_auth_id: String,
        authorization_code: String,
        code_verifier: String,
        access_token: String,
        refresh_token: String,
    }

    #[cfg(unix)]
    impl DeviceFlowSecrets {
        fn generated() -> Self {
            let id = uuid::Uuid::new_v4().simple().to_string();
            Self {
                device_auth_id: format!("SYNTHETIC_DEVICE_AUTH_ID_{id}"),
                authorization_code: format!("SYNTHETIC_AUTH_CODE_{id}"),
                code_verifier: format!(
                    "{id}abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
                ),
                access_token: format!("SYNTHETIC_ACCESS_TOKEN_{id}"),
                refresh_token: format!("SYNTHETIC_REFRESH_TOKEN_{id}"),
            }
        }

        fn private_values(&self) -> [&str; 5] {
            [
                &self.device_auth_id,
                &self.authorization_code,
                &self.code_verifier,
                &self.access_token,
                &self.refresh_token,
            ]
        }
    }

    #[cfg(unix)]
    struct DevicePipeObservation {
        attempt: usize,
        bytes: Vec<u8>,
        ttl_seconds: u64,
        completed_at: Instant,
    }

    #[cfg(unix)]
    struct DeviceTlsRequest {
        method: String,
        path: String,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
        received_at: Instant,
        recorded_at: Instant,
        pipe_completed_at: Option<Instant>,
    }

    #[cfg(unix)]
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum DeviceTlsStage {
        Start,
        Poll,
        Exchange,
        Unexpected,
    }

    #[cfg(unix)]
    struct DeviceTlsSequence {
        issuer: String,
        roots: rustls::RootCertStore,
        output_sender: mpsc::Sender<DevicePipeObservation>,
        shutdown: Arc<AtomicBool>,
        worker: Option<std::thread::JoinHandle<Result<Vec<DeviceTlsRequest>, &'static str>>>,
        started_at: Instant,
    }

    #[cfg(unix)]
    impl DeviceTlsSequence {
        fn start(secrets: Vec<DeviceFlowSecrets>, complete: bool) -> Self {
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .expect("generate the owned localhost test certificate");
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(certified.cert.der().clone())
                .expect("trust the owned test CA");
            let tls = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certified.cert.der().clone()],
                    PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
                )
                .expect("build the owned localhost TLS server");
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral loopback TLS");
            listener
                .set_nonblocking(true)
                .expect("make listener bounded");
            let issuer = format!(
                "https://localhost:{}",
                listener.local_addr().unwrap().port()
            );
            let device_url = format!("{issuer}/codex/device");
            let (output_sender, output_receiver) = mpsc::channel();
            let shutdown = Arc::new(AtomicBool::new(false));
            let worker_shutdown = Arc::clone(&shutdown);
            let started_at = Instant::now();
            let worker = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| "TLS fixture runtime setup failed")?;
                runtime.block_on(run_device_tls_sequence(
                    listener,
                    Arc::new(tls),
                    secrets,
                    complete,
                    device_url,
                    output_receiver,
                    worker_shutdown,
                ))
            });
            Self {
                issuer,
                roots,
                output_sender,
                shutdown,
                worker: Some(worker),
                started_at,
            }
        }

        fn device_url(&self) -> String {
            format!("{}/codex/device", self.issuer)
        }

        fn roots(&self) -> rustls::RootCertStore {
            self.roots.clone()
        }

        fn observe_pipe(
            &self,
            read_fd: std::os::fd::OwnedFd,
            attempt: usize,
        ) -> std::thread::JoinHandle<Result<DevicePipeObservation, &'static str>> {
            let sender = self.output_sender.clone();
            let url = self.device_url();
            std::thread::spawn(move || {
                let observed = read_completed_device_instruction(read_fd, attempt, &url)?;
                sender
                    .send(DevicePipeObservation {
                        attempt: observed.attempt,
                        bytes: observed.bytes.clone(),
                        ttl_seconds: observed.ttl_seconds,
                        completed_at: observed.completed_at,
                    })
                    .map_err(|_| "TLS fixture output gate closed")?;
                Ok(observed)
            })
        }

        fn finish(&mut self) -> Result<Vec<DeviceTlsRequest>, &'static str> {
            let worker = self.worker.take().expect("TLS worker is owned");
            let result = worker.join();
            self.shutdown.store(true, Ordering::Release);
            result.map_err(|_| "TLS fixture worker panicked")?
        }
    }

    #[cfg(unix)]
    impl Drop for DeviceTlsSequence {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Release);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    #[cfg(unix)]
    fn commands_runner() -> crate::runtime::AuthEntryRunner {
        crate::runtime::AuthEntryRunner::from_bundle("rss/auth/commands.rss", COMMANDS_SOURCES)
            .expect("compile the complete production auth command bundle")
    }

    #[cfg(unix)]
    struct UnavailableCallback;

    #[cfg(unix)]
    impl crate::auth::oauth::CallbackWaiter for UnavailableCallback {
        fn wait_one(
            &self,
            context: &OAuthIoContext,
        ) -> Result<crate::auth::oauth::RawCallbackInput, OAuthError> {
            context.check()?;
            Err(OAuthError::Transport {
                message: "composition test callback unavailable".to_owned(),
            })
        }
    }

    #[cfg(unix)]
    struct UnavailableBrowser;

    #[cfg(unix)]
    impl crate::auth::oauth::BrowserOpener for UnavailableBrowser {
        fn open(&self, _: &str, context: &OAuthIoContext) -> Result<(), OAuthError> {
            context.check()?;
            Err(OAuthError::Transport {
                message: "composition test browser unavailable".to_owned(),
            })
        }
    }

    #[cfg(unix)]
    fn run_native_login(
        runner: &crate::runtime::AuthEntryRunner,
        home: &std::path::Path,
        roots: rustls::RootCertStore,
        sender: crate::auth::host::DeviceInstructionSender,
        cancellation: &crate::runtime::RunCancellation,
    ) -> Result<rustscript_vm::Value, crate::runtime::AuthEntryError> {
        let home = home.to_path_buf();
        runner.run_with_host_factory(
            crate::runtime::AuthCommandInput {
                operation: "auth.login".to_owned(),
                provider: Some("openai-codex".to_owned()),
                credential_id: None,
            },
            cancellation,
            move |child| {
                let oauth = Arc::new(crate::auth::oauth::OAuthHost::new(
                    Arc::new(NativeHttpsTransport::with_roots(roots)),
                    Arc::new(UnavailableCallback),
                    Arc::new(UnavailableBrowser),
                    Arc::new(crate::auth::host::SystemOAuthClock),
                    Arc::new(crate::auth::host::RunOAuthCancel::new(child.clone())),
                ));
                Ok(crate::auth::host::AuthHost::new_for_login(home, child)?
                    .with_oauth_host(oauth)
                    .with_device_instruction_sender(sender))
            },
        )
    }

    #[cfg(unix)]
    struct DeviceLoginHome(std::path::PathBuf);

    #[cfg(unix)]
    impl DeviceLoginHome {
        fn configured(issuer: &str, seed_unrelated: bool) -> Self {
            let assigned = std::path::PathBuf::from(
                std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP")
                    .expect("assigned Task6 test TEMP is configured"),
            );
            std::fs::create_dir_all(&assigned).expect("create assigned test TEMP");
            let home = assigned.join(format!("native-https-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&home).expect("create isolated login home");
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
                .expect("protect isolated login home");

            let mut config =
                include_str!("../../tests/fixtures/codex_device/config.yaml").to_owned();
            for (old, new) in [
                (
                    "issuer: https://auth.example.test",
                    format!("issuer: {issuer}"),
                ),
                (
                    "token_endpoint: https://auth.example.test/oauth/token",
                    format!("token_endpoint: {issuer}/oauth/token"),
                ),
                (
                    "redirect_uri: https://auth.example.test/deviceauth/callback",
                    format!("redirect_uri: {issuer}/deviceauth/callback"),
                ),
            ] {
                assert_eq!(
                    config.matches(old).count(),
                    1,
                    "rewrite one configured OAuth URL"
                );
                config = config.replace(old, &new);
            }
            if seed_unrelated {
                let marker = "      refresh_skew_seconds: 120\n";
                assert_eq!(
                    config.matches(marker).count(),
                    1,
                    "retain one OAuth provider block"
                );
                config = config.replace(
                    marker,
                    "      refresh_skew_seconds: 120\n  unrelated-provider:\n    protocol: codex-responses\n    base_url: https://other.example.test/backend\n    auth: unrelated-primary\n",
                );
            }
            let config_path = home.join("config.yaml");
            std::fs::write(&config_path, config).expect("write private configured OAuth policy");
            std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
                .expect("protect configured OAuth policy");
            if seed_unrelated {
                let id = uuid::Uuid::new_v4().simple().to_string();
                let auth = format!(
                    "version: 1\ncredentials:\n  unrelated-primary:\n    provider: unrelated-provider\n    kind: oauth\n    source: fixture\n    token_type: Bearer\n    access_token: SYNTHETIC_UNRELATED_ACCESS_{id}\n    refresh_token: SYNTHETIC_UNRELATED_REFRESH_{id}\n    expires_at_ms: 1900000000000\n    scopes: [scope.fixture]\n    account_id: unrelated.synthetic\n    generation: 7\n    status: active\n"
                );
                let auth_path = home.join("auth.yaml");
                std::fs::write(&auth_path, auth).expect("seed configured unrelated credential");
                std::fs::set_permissions(&auth_path, std::fs::Permissions::from_mode(0o600))
                    .expect("protect unrelated credential record");
            }
            Self(home)
        }

        fn entries(&self) -> Vec<String> {
            let mut entries = std::fs::read_dir(&self.0)
                .expect("read isolated home entries")
                .map(|entry| {
                    entry
                        .expect("read isolated home entry")
                        .file_name()
                        .into_string()
                        .expect("UTF-8 isolated home entry")
                })
                .collect::<Vec<_>>();
            entries.sort();
            entries
        }
    }

    #[cfg(unix)]
    impl Drop for DeviceLoginHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    fn native_pipe() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
        let mut fds = [-1; 2];
        // SAFETY: `fds` has room for the two descriptors returned by pipe2.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: pipe2 returned two newly owned descriptors.
        unsafe {
            (
                std::os::fd::OwnedFd::from_raw_fd(fds[0]),
                std::os::fd::OwnedFd::from_raw_fd(fds[1]),
            )
        }
    }

    #[cfg(unix)]
    fn read_completed_device_instruction(
        read_fd: std::os::fd::OwnedFd,
        attempt: usize,
        expected_url: &str,
    ) -> Result<DevicePipeObservation, &'static str> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut bytes = Vec::new();
        while bytes.iter().filter(|byte| **byte == b'\n').count() < 3 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("native pipe output timed out");
            }
            let mut descriptor = libc::pollfd {
                fd: read_fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let timeout_ms = remaining.as_millis().clamp(1, 50) as libc::c_int;
            // SAFETY: descriptor points to one valid pollfd and uses a finite timeout.
            let ready = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
            if ready == 0 {
                continue;
            }
            if ready < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err("native pipe poll failed");
            }
            if descriptor.revents & (libc::POLLNVAL | libc::POLLERR) != 0
                || descriptor.revents & libc::POLLHUP != 0 && descriptor.revents & libc::POLLIN == 0
            {
                return Err("native pipe closed before instruction completion");
            }
            let mut chunk = [0u8; 256];
            // SAFETY: chunk is writable and read_fd remains owned by this function.
            let count =
                unsafe { libc::read(read_fd.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
            if count <= 0 {
                return Err("native pipe read failed");
            }
            bytes.extend_from_slice(&chunk[..count as usize]);
            if bytes.len() > 4096 {
                return Err("native instruction exceeded its output bound");
            }
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| "native instruction was not UTF-8")?;
        let lines = text.lines().collect::<Vec<_>>();
        if lines.len() != 3
            || lines[0] != format!("Open {expected_url}")
            || lines[1] != format!("Code: {DEVICE_USER_CODE}")
        {
            return Err("native instruction lines did not match public login data");
        }
        let ttl = lines[2]
            .strip_prefix("Expires in ")
            .and_then(|line| line.strip_suffix(" seconds"))
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| (1..=900).contains(value))
            .ok_or("native instruction TTL was invalid")?;
        if text
            != format!("Open {expected_url}\nCode: {DEVICE_USER_CODE}\nExpires in {ttl} seconds\n")
        {
            return Err("native instruction was not exactly three completed lines");
        }
        Ok(DevicePipeObservation {
            attempt,
            bytes,
            ttl_seconds: ttl,
            completed_at: Instant::now(),
        })
    }

    #[cfg(unix)]
    async fn run_device_tls_sequence(
        listener: TcpListener,
        tls: Arc<rustls::ServerConfig>,
        secrets: Vec<DeviceFlowSecrets>,
        complete: bool,
        device_url: String,
        output_receiver: mpsc::Receiver<DevicePipeObservation>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Vec<DeviceTlsRequest>, &'static str> {
        let listener = tokio::net::TcpListener::from_std(listener)
            .map_err(|_| "TLS fixture listener setup failed")?;
        let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(tls));
        let output_receiver = Arc::new(std::sync::Mutex::new(output_receiver));
        let expected_count = if complete { secrets.len() * 3 } else { 1 };
        let mut records = Vec::with_capacity(expected_count);
        for request_index in 0..expected_count {
            let deadline = Instant::now() + Duration::from_secs(3);
            let tcp = accept_device_connection(&listener, &shutdown, deadline)
                .await?
                .ok_or("TLS fixture did not receive the expected request")?;
            let flow = request_index / 3;
            let stage = if !complete {
                DeviceTlsStage::Start
            } else {
                match request_index % 3 {
                    0 => DeviceTlsStage::Start,
                    1 => DeviceTlsStage::Poll,
                    _ => DeviceTlsStage::Exchange,
                }
            };
            records.push(
                serve_device_tls_request(
                    tcp,
                    Arc::clone(&acceptor),
                    (stage, flow),
                    &secrets[flow],
                    &device_url,
                    &output_receiver,
                    &shutdown,
                )
                .await?,
            );
        }
        if !complete {
            let absence_deadline = Instant::now() + Duration::from_millis(1300);
            if let Some(tcp) =
                accept_device_connection(&listener, &shutdown, absence_deadline).await?
            {
                let unexpected = serve_device_tls_request(
                    tcp,
                    Arc::clone(&acceptor),
                    (DeviceTlsStage::Unexpected, 0),
                    &secrets[0],
                    &device_url,
                    &output_receiver,
                    &shutdown,
                )
                .await?;
                records.push(unexpected);
                return Err("an unexpected native request followed output failure");
            }
        }
        Ok(records)
    }

    #[cfg(unix)]
    async fn accept_device_connection(
        listener: &tokio::net::TcpListener,
        shutdown: &AtomicBool,
        deadline: Instant,
    ) -> Result<Option<tokio::net::TcpStream>, &'static str> {
        loop {
            if shutdown.load(Ordering::Acquire) {
                return Err("TLS fixture stopped during accept");
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            tokio::select! {
                accepted = listener.accept() => {
                    return accepted
                        .map(|(stream, _)| Some(stream))
                        .map_err(|_| "TLS fixture accept failed");
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
    }

    #[cfg(unix)]
    async fn serve_device_tls_request(
        tcp: tokio::net::TcpStream,
        acceptor: Arc<tokio_rustls::TlsAcceptor>,
        stage_flow: (DeviceTlsStage, usize),
        secrets: &DeviceFlowSecrets,
        expected_url: &str,
        output_receiver: &Arc<std::sync::Mutex<mpsc::Receiver<DevicePipeObservation>>>,
        shutdown: &Arc<AtomicBool>,
    ) -> Result<DeviceTlsRequest, &'static str> {
        let (stage, flow) = stage_flow;
        let tls = tokio::time::timeout(Duration::from_secs(2), acceptor.accept(tcp))
            .await
            .map_err(|_| "TLS fixture handshake timed out")?
            .map_err(|_| "TLS fixture handshake failed")?;
        let output = match stage {
            DeviceTlsStage::Start => format!(
                "{{\"device_auth_id\":\"{}\",\"user_code\":\"{DEVICE_USER_CODE}\",\"expires_in\":900,\"interval\":1}}",
                secrets.device_auth_id
            ),
            DeviceTlsStage::Poll => format!(
                "{{\"authorization_code\":\"{}\",\"code_verifier\":\"{}\",\"public\":\"poll-ok\"}}",
                secrets.authorization_code, secrets.code_verifier
            ),
            DeviceTlsStage::Exchange => format!(
                "{{\"access_token\":\"{}\",\"refresh_token\":\"{}\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"public\":\"exchange-ok\"}}",
                secrets.access_token, secrets.refresh_token
            ),
            DeviceTlsStage::Unexpected => String::new(),
        };
        let status = if stage == DeviceTlsStage::Unexpected {
            500
        } else {
            200
        };
        let result_slot = Arc::new(std::sync::Mutex::new(None));
        let service_slot = Arc::clone(&result_slot);
        let service_receiver = Arc::clone(output_receiver);
        let expected_url = expected_url.to_owned();
        let response_body = output.into_bytes();
        let service = service_fn(move |request: Request<hyper::body::Incoming>| {
            let slot = Arc::clone(&service_slot);
            let receiver = Arc::clone(&service_receiver);
            let expected_url = expected_url.clone();
            let response_body = response_body.clone();
            async move {
                let result =
                    read_device_tls_request(request, stage, flow, &expected_url, &receiver).await;
                let successful = result.is_ok();
                *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(result);
                let response = Response::builder()
                    .status(if successful { status } else { 500 })
                    .header(hyper::header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(response_body)))
                    .expect("build bounded TLS fixture response");
                Ok::<_, Infallible>(response)
            }
        });
        let connection = http1::Builder::new().serve_connection(TokioIo::new(tls), service);
        tokio::select! {
            _ = tokio::time::timeout(Duration::from_secs(3), connection) => {},
            _ = wait_for_device_shutdown(shutdown) => return Err("TLS fixture stopped during HTTP"),
        }
        result_slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .ok_or("TLS fixture did not receive an HTTP request")?
    }

    #[cfg(unix)]
    async fn wait_for_device_shutdown(shutdown: &AtomicBool) {
        while !shutdown.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[cfg(unix)]
    async fn read_device_tls_request(
        request: Request<hyper::body::Incoming>,
        stage: DeviceTlsStage,
        flow: usize,
        expected_url: &str,
        output_receiver: &Arc<std::sync::Mutex<mpsc::Receiver<DevicePipeObservation>>>,
    ) -> Result<DeviceTlsRequest, &'static str> {
        let received_at = Instant::now();
        let (parts, mut body) = request.into_parts();
        let method = parts.method.as_str().to_owned();
        let path = parts
            .uri
            .path_and_query()
            .map(|path| path.as_str().to_owned())
            .unwrap_or_else(|| "/".to_owned());
        let mut headers = BTreeMap::new();
        for (name, value) in &parts.headers {
            if headers
                .insert(
                    name.as_str().to_owned(),
                    value
                        .to_str()
                        .map_err(|_| "TLS fixture received a non-text header")?
                        .to_owned(),
                )
                .is_some()
            {
                return Err("TLS fixture received a duplicate request header");
            }
        }
        let mut request_body = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| "TLS fixture request body failed")?;
            if let Some(data) = frame.data_ref() {
                if request_body.len().saturating_add(data.len()) > 64 * 1024 {
                    return Err("TLS fixture request body exceeded its bound");
                }
                request_body.extend_from_slice(data);
            }
        }
        let pipe_completed_at = if stage == DeviceTlsStage::Poll {
            let observation = output_receiver
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .recv_timeout(Duration::from_secs(3))
                .map_err(|_| "TLS fixture did not observe completed native output")?;
            if observation.attempt != flow
                || public_device_instruction_ttl(&observation.bytes, expected_url)
                    != Some(observation.ttl_seconds)
            {
                return Err("TLS fixture observed mismatched native output");
            }
            Some(observation.completed_at)
        } else {
            None
        };
        let recorded_at = Instant::now();
        Ok(DeviceTlsRequest {
            method,
            path,
            headers,
            body: request_body,
            received_at,
            recorded_at,
            pipe_completed_at,
        })
    }

    #[cfg(unix)]
    fn public_device_instruction_ttl(bytes: &[u8], expected_url: &str) -> Option<u64> {
        let text = std::str::from_utf8(bytes).ok()?;
        let lines = text.lines().collect::<Vec<_>>();
        if lines.len() != 3
            || lines[0] != format!("Open {expected_url}")
            || lines[1] != format!("Code: {DEVICE_USER_CODE}")
        {
            return None;
        }
        let ttl = lines[2]
            .strip_prefix("Expires in ")?
            .strip_suffix(" seconds")?
            .parse::<u64>()
            .ok()?;
        if !(1..=900).contains(&ttl)
            || text
                != format!(
                    "Open {expected_url}\nCode: {DEVICE_USER_CODE}\nExpires in {ttl} seconds\n"
                )
        {
            return None;
        }
        Some(ttl)
    }

    #[cfg(unix)]
    fn assert_login_succeeded(result: &rustscript_vm::Value, generation: i64) {
        assert!(matches!(
            vm_field(result, "ok"),
            rustscript_vm::Value::Bool(true)
        ));
        assert!(
            matches!(vm_field(result, "generation"), rustscript_vm::Value::Int(value) if *value == generation)
        );
        let rustscript_vm::Value::String(status) = vm_field(result, "status") else {
            panic!("RSS login returned a non-string status");
        };
        let row: serde_json::Value =
            serde_json::from_str(status).expect("parse sanitized RSS login report");
        assert!(row["status"] == "active", "RSS login status was not active");
        assert!(
            row["generation"] == generation,
            "RSS report generation differed from the native store"
        );
    }

    #[cfg(unix)]
    fn assert_login_failed(result: &rustscript_vm::Value, code: &str) {
        assert!(matches!(
            vm_field(result, "ok"),
            rustscript_vm::Value::Bool(false)
        ));
        for field in ["status", "error"] {
            let rustscript_vm::Value::String(value) = vm_field(result, field) else {
                panic!("RSS login failure returned a non-string {field}");
            };
            assert_eq!(value.as_ref(), code, "RSS login failure field {field}");
        }
    }

    #[cfg(unix)]
    fn vm_field<'a>(value: &'a rustscript_vm::Value, name: &str) -> &'a rustscript_vm::Value {
        let rustscript_vm::Value::Map(fields) = value else {
            panic!("RSS result is not a record");
        };
        fields
            .iter()
            .find_map(|(key, value)| match key {
                rustscript_vm::Value::String(key) if key.as_ref() == name => Some(value),
                _ => None,
            })
            .unwrap_or_else(|| panic!("RSS result omitted a required field"))
    }

    #[cfg(unix)]
    fn assert_private_values_absent(value: &str, secrets: &[DeviceFlowSecrets]) {
        for secret in secrets {
            for private in secret.private_values() {
                assert!(
                    !value.contains(private),
                    "private OAuth material leaked from the native boundary"
                );
            }
        }
    }

    #[cfg(unix)]
    fn assert_native_store_contents(
        stored: &[u8],
        secrets: &[DeviceFlowSecrets],
        current_generation: usize,
    ) {
        let contains = |value: &str| {
            stored
                .windows(value.len())
                .any(|candidate| candidate == value.as_bytes())
        };
        let current = &secrets[current_generation];
        for transient in [
            &current.device_auth_id,
            &current.authorization_code,
            &current.code_verifier,
        ] {
            assert!(
                !contains(transient),
                "transient OAuth material was persisted"
            );
        }
        assert!(
            contains(&current.access_token),
            "native store omitted access token"
        );
        assert!(
            contains(&current.refresh_token),
            "native store omitted refresh token"
        );
        for previous in &secrets[..current_generation] {
            assert!(
                !contains(&previous.access_token),
                "older access token remained active"
            );
            assert!(
                !contains(&previous.refresh_token),
                "older refresh token remained active"
            );
        }
    }

    #[cfg(unix)]
    fn assert_device_request_records(
        records: &[DeviceTlsRequest],
        secrets: &[DeviceFlowSecrets],
        issuer: &str,
        pipes: &[DevicePipeObservation],
    ) {
        assert_eq!(
            records.len(),
            secrets.len() * 3,
            "the local TLS service saw exactly three requests per invocation"
        );
        for (flow, secret) in secrets.iter().enumerate() {
            let start = &records[flow * 3];
            let poll = &records[flow * 3 + 1];
            let exchange = &records[flow * 3 + 2];
            assert!(
                start.method == "POST" && start.path == DEVICE_START_PATH,
                "device start request path or method differed"
            );
            assert!(
                poll.method == "POST" && poll.path == DEVICE_POLL_PATH,
                "device poll request path or method differed"
            );
            assert!(
                exchange.method == "POST" && exchange.path == DEVICE_TOKEN_PATH,
                "token exchange request path or method differed"
            );
            assert!(
                start
                    .headers
                    .get("content-type")
                    .is_some_and(|v| v == "application/json")
            );
            assert!(
                poll.headers
                    .get("content-type")
                    .is_some_and(|v| v == "application/json")
            );
            assert!(
                exchange
                    .headers
                    .get("content-type")
                    .is_some_and(|v| v == "application/x-www-form-urlencoded")
            );
            assert!(
                start
                    .headers
                    .get("host")
                    .is_some_and(|v| v == issuer.trim_start_matches("https://"))
            );
            assert!(
                poll.headers
                    .get("host")
                    .is_some_and(|v| v == issuer.trim_start_matches("https://"))
            );
            assert!(
                exchange
                    .headers
                    .get("host")
                    .is_some_and(|v| v == issuer.trim_start_matches("https://"))
            );
            assert!(
                !start.headers.contains_key("authorization")
                    && !poll.headers.contains_key("authorization")
                    && !exchange.headers.contains_key("authorization")
            );
            assert!(
                start.body.len() <= 64 * 1024
                    && poll.body.len() <= 64 * 1024
                    && exchange.body.len() <= 64 * 1024
            );
            let start_json: serde_json::Value =
                serde_json::from_slice(&start.body).expect("parse bounded start JSON");
            assert!(
                start_json.as_object().is_some_and(|map| map.len() == 1
                    && map.get("client_id").is_some_and(|v| v == DEVICE_CLIENT_ID)),
                "device start body did not retain the configured client id"
            );
            let poll_json: serde_json::Value =
                serde_json::from_slice(&poll.body).expect("parse bounded poll JSON");
            assert!(
                poll_json.as_object().is_some_and(|map| map.len() == 2
                    && map
                        .get("user_code")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|v| v == DEVICE_USER_CODE)
                    && map
                        .get("device_auth_id")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|v| v == secret.device_auth_id)),
                "device poll did not carry the native opaque device credential"
            );
            let expected_exchange = format!(
                "grant_type=authorization_code&client_id={DEVICE_CLIENT_ID}&code={}&code_verifier={}&redirect_uri=https%3A%2F%2Flocalhost%3A{}%2Fdeviceauth%2Fcallback",
                secret.authorization_code,
                secret.code_verifier,
                issuer
                    .trim_start_matches("https://")
                    .strip_prefix("localhost:")
                    .unwrap_or_default(),
            );
            assert!(
                exchange.body == expected_exchange.as_bytes(),
                "token exchange form did not carry the opaque code/verifier pair and configured redirect URI"
            );
            let output = &pipes[flow];
            assert!(
                poll.pipe_completed_at == Some(output.completed_at)
                    && poll.recorded_at >= output.completed_at,
                "the TLS service recorded/permitted poll before observing completed native pipe bytes"
            );
        }
    }

    #[cfg(unix)]
    fn print_device_request_evidence(
        records: &[DeviceTlsRequest],
        start: Instant,
        outputs: &[DevicePipeObservation],
    ) {
        for (index, request) in records.iter().enumerate() {
            let elapsed_ms = request.received_at.duration_since(start).as_millis();
            let host = request
                .headers
                .get("host")
                .map(String::as_str)
                .unwrap_or("missing");
            let content_type = request
                .headers
                .get("content-type")
                .map(String::as_str)
                .unwrap_or("missing");
            let pipe_elapsed_ms = request
                .pipe_completed_at
                .map(|completed| completed.duration_since(start).as_millis());
            println!(
                "P_NATIVE_TLS_RECORD request={index} method={} path={} host={} content_type={} bounded_body_bytes={} received_ms={} recorded_ms={} pipe_completed_ms={pipe_elapsed_ms:?}",
                request.method,
                request.path,
                host,
                content_type,
                request.body.len(),
                elapsed_ms,
                request.recorded_at.duration_since(start).as_millis(),
            );
        }
        for output in outputs {
            println!(
                "P_NATIVE_PIPE_COMPLETED attempt={} lines=3 ttl_seconds={} elapsed_ms={}",
                output.attempt,
                output.ttl_seconds,
                output.completed_at.duration_since(start).as_millis(),
            );
        }
    }

    #[cfg(unix)]
    fn assert_unrelated_record_unchanged(before: &[u8], after: &[u8]) {
        let before =
            crate::auth::config::parse_stored_yaml(std::path::Path::new("before auth"), before)
                .expect("parse seeded auth YAML");
        let after =
            crate::auth::config::parse_stored_yaml(std::path::Path::new("after auth"), after)
                .expect("parse persisted auth YAML");
        let before_record = before.credentials.get("unrelated-primary");
        let after_record = after.credentials.get("unrelated-primary");
        assert!(
            before_record.is_some() && before_record == after_record,
            "complete unrelated credential record changed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn real_commands_tls_pipe_completion_and_native_store_relogin_generations() {
        let runner = commands_runner();
        let secrets = vec![
            DeviceFlowSecrets::generated(),
            DeviceFlowSecrets::generated(),
        ];
        let mut server = DeviceTlsSequence::start(secrets.clone(), true);
        let home = DeviceLoginHome::configured(&server.issuer, true);
        let config_before =
            std::fs::read(home.0.join("config.yaml")).expect("configured policy bytes");
        let auth_before =
            std::fs::read(home.0.join("auth.yaml")).expect("unrelated credential bytes");
        let before_store = crate::auth::store::AuthStore::from_home(&home.0)
            .expect("open configured native store");
        let unrelated_before = before_store
            .load_metadata("unrelated-primary")
            .expect("load configured unrelated metadata");
        drop(before_store);

        let mut pipe_observations = Vec::new();
        for attempt in 0..2 {
            let (read_fd, write_fd) = native_pipe();
            let reader = server.observe_pipe(read_fd, attempt);
            let sink: Arc<dyn crate::auth::host::DeviceInstructionSink> = Arc::new(
                crate::auth::host::NativeDeviceInstructionOutput::from_fd(write_fd),
            );
            let sender = crate::auth::host::DeviceInstructionSender::from_sink(sink);
            let cancellation =
                crate::runtime::RunCancellation::with_timeout(Duration::from_secs(10));
            let result = run_native_login(&runner, &home.0, server.roots(), sender, &cancellation)
                .expect("execute the actual auth.login command entry");
            let output = reader
                .join()
                .expect("join owned native pipe reader")
                .expect("observe completed three-line output");
            assert_eq!(output.attempt, attempt);
            assert!(
                public_device_instruction_ttl(&output.bytes, &server.device_url())
                    == Some(output.ttl_seconds)
            );
            let rendered =
                String::from_utf8(output.bytes.clone()).expect("public pipe output is UTF-8");
            assert_private_values_absent(&rendered, &secrets);
            assert_login_succeeded(&result, (attempt + 1) as i64);
            assert_private_values_absent(&format!("{result:?}"), &secrets);
            let store = crate::auth::store::AuthStore::from_home(&home.0)
                .expect("open native store after completed login");
            let metadata = store
                .load_metadata("fixture-codex")
                .expect("read native credential generation");
            assert_eq!(metadata.generation, (attempt + 1) as u64);
            let stored = std::fs::read(home.0.join("auth.yaml"))
                .expect("read only the native store after login completion");
            assert_native_store_contents(&stored, &secrets, attempt);
            pipe_observations.push(output);
        }

        let records = server.finish().expect("join finite local TLS sequence");
        print_device_request_evidence(&records, server.started_at, &pipe_observations);
        assert_device_request_records(&records, &secrets, &server.issuer, &pipe_observations);
        assert_eq!(
            std::fs::read(home.0.join("config.yaml"))
                .expect("configuration remains byte-identical"),
            config_before
        );
        let auth_after =
            std::fs::read(home.0.join("auth.yaml")).expect("native auth store after two logins");
        assert_unrelated_record_unchanged(&auth_before, &auth_after);
        let store =
            crate::auth::store::AuthStore::from_home(&home.0).expect("reopen native auth store");
        let first = store
            .load_metadata("fixture-codex")
            .expect("read generation two from native store");
        let unrelated_after = store
            .load_metadata("unrelated-primary")
            .expect("read preserved unrelated metadata");
        assert_eq!(first.generation, 2);
        assert_eq!(unrelated_after, unrelated_before);
        assert_eq!(
            store
                .load_all_metadata()
                .expect("read configured records")
                .len(),
            2
        );
        assert!(
            auth_after
                .windows(secrets[1].access_token.len())
                .any(|bytes| bytes == secrets[1].access_token.as_bytes())
        );
        assert!(
            auth_after
                .windows(secrets[1].refresh_token.len())
                .any(|bytes| bytes == secrets[1].refresh_token.as_bytes())
        );
        assert_private_values_absent(&format!("{first:?}{unrelated_after:?}"), &secrets);
    }

    #[cfg(unix)]
    fn assert_device_start_record(record: &DeviceTlsRequest, issuer: &str) {
        assert_eq!(record.method, "POST");
        assert_eq!(record.path, DEVICE_START_PATH);
        assert_eq!(
            record.headers.get("host").map(String::as_str),
            Some(issuer.trim_start_matches("https://"))
        );
        assert_eq!(
            record.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        let body: serde_json::Value =
            serde_json::from_slice(&record.body).expect("parse bounded device start JSON");
        assert!(body.as_object().is_some_and(|object| {
            object.len() == 1
                && object.get("client_id").and_then(serde_json::Value::as_str)
                    == Some(DEVICE_CLIENT_ID)
        }));
    }

    #[cfg(unix)]
    #[test]
    fn dev_full_stops_real_commands_tls_login_after_device_start_without_store_mutation() {
        let runner = commands_runner();
        let secret = DeviceFlowSecrets::generated();
        let mut server = DeviceTlsSequence::start(vec![secret.clone()], false);
        let home = DeviceLoginHome::configured(&server.issuer, false);
        let config_path = home.0.join("config.yaml");
        let config_before = std::fs::read(&config_path).expect("configured local provider bytes");
        let entries_before = home.entries();
        let output = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("open the assigned Unix full device");
        let sink: Arc<dyn crate::auth::host::DeviceInstructionSink> = Arc::new(
            crate::auth::host::NativeDeviceInstructionOutput::from_fd(output.into()),
        );
        let sender = crate::auth::host::DeviceInstructionSender::from_sink(sink);
        let cancellation = crate::runtime::RunCancellation::with_timeout(Duration::from_secs(10));

        let result = run_native_login(&runner, &home.0, server.roots(), sender, &cancellation)
            .expect("RSS returns the native output failure as a sanitized result");
        assert_login_failed(&result, "ui_sink_closed");
        assert_private_values_absent(&format!("{result:?}"), &[secret]);
        let records = server
            .finish()
            .expect("finish the bounded no-more-requests observation");
        print_device_request_evidence(&records, server.started_at, &[]);
        assert_eq!(
            records.len(),
            1,
            "TLS served only the actual device-start operation"
        );
        assert_device_start_record(&records[0], &server.issuer);
        assert_eq!(
            std::fs::read(&config_path).expect("configuration remains unchanged"),
            config_before
        );
        assert_eq!(
            home.entries(),
            entries_before,
            "output failure created no auth store or lock"
        );
        assert!(!home.0.join("auth.yaml").exists());
        assert!(!home.0.join("auth.yaml.lock").exists());
    }
}
