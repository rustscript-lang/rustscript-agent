//! Exercise the production gateway over an owned loopback HTTP socket.
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Request, StatusCode, client::conn::http1};
use hyper_util::rt::TokioIo;
use rustscript_agent::{AgentGatewayState, build_agent_gateway_app};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};

pub const LOCAL_BEARER: &str = "synthetic-live-delivery-observer";
const MAX_DELIVERY_BYTES: usize = 4 * 1024 * 1024;
pub struct Observer {
    address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    server: Option<JoinHandle<std::io::Result<()>>>,
    connection: Option<JoinHandle<Result<(), hyper::Error>>>,
    collector: Option<JoinHandle<Vec<u8>>>,
    session_id: Option<String>,
    http_trace: Vec<Value>,
}
pub struct Receipt {
    pub wire: String,
    pub events: Vec<Value>,
    pub listener_closed: bool,
    pub http_trace: Vec<Value>,
}
impl Observer {
    async fn bind(state: AgentGatewayState) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("owned delivery listener");
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, build_agent_gateway_app(state))
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        Self {
            address,
            shutdown: Some(shutdown_tx),
            server: Some(server),
            connection: None,
            collector: None,
            session_id: None,
            http_trace: Vec::new(),
        }
    }

    async fn request_json(
        &mut self,
        method: &str,
        path: &str,
        body: Value,
        authenticated: bool,
    ) -> (u16, Value) {
        let stream = TcpStream::connect(self.address)
            .await
            .expect("connect owned API Server");
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .expect("HTTP request handshake");
        let driver = tokio::spawn(connection);
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", self.address.to_string())
            .header("content-type", "application/json");
        if authenticated {
            request = request.header("authorization", format!("Bearer {LOCAL_BEARER}"));
        }
        let payload = if body.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(&body).unwrap()
        };
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_request(
                request
                    .body(Full::new(bytes::Bytes::from(payload)))
                    .unwrap(),
            ),
        )
        .await
        .expect("bounded API response head")
        .expect("API response");
        let status = response.status().as_u16();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = tokio::time::timeout(Duration::from_secs(10), body.frame())
            .await
            .expect("bounded JSON body")
        {
            let frame = frame.expect("API JSON response frame");
            if let Some(data) = frame.data_ref() {
                assert!(bytes.len().saturating_add(data.len()) <= MAX_DELIVERY_BYTES);
                bytes.extend_from_slice(data);
            }
        }
        drop(sender);
        driver.abort();
        let _ = driver.await;
        let value: Value = serde_json::from_slice(&bytes).expect("actual API JSON");
        self.http_trace.push(json!({"method":method,"path":path,"authenticated":authenticated,"status":status,"response":value}));
        (status, value)
    }

    pub async fn start(state: AgentGatewayState, run_id: &str) -> Self {
        let mut observer = Self::bind(state).await;
        observer.attach(run_id).await;
        observer
    }

    pub async fn admit_http(
        state: AgentGatewayState,
        prompt: &str,
        provider: &str,
        model: &str,
        workspace: &str,
    ) -> (Self, String, String) {
        let mut observer = Self::bind(state).await;
        assert_eq!(
            observer
                .request_json("GET", "/api/sessions", Value::Null, false)
                .await
                .0,
            401
        );
        assert_eq!(
            observer
                .request_json("GET", "/health/detailed", Value::Null, true)
                .await
                .0,
            200
        );
        assert_eq!(
            observer
                .request_json("GET", "/v1/models", Value::Null, true)
                .await
                .0,
            200
        );
        let (status, session) = observer
            .request_json(
                "POST",
                "/api/sessions",
                json!({"source":"api_server-live-e2e","model":model,"provider":provider}),
                true,
            )
            .await;
        assert_eq!(status, 201);
        let session_id = session["session"]["id"]
            .as_str()
            .expect("HTTP-created session ID")
            .to_owned();
        let (status, run) = observer.request_json("POST", "/v1/runs", json!({"session_id":session_id,"input":prompt,"provider":provider,"model":model,"workspace":workspace}), true).await;
        assert_eq!(status, 202, "actual HTTP admission response: {run}");
        let run_id = run["run_id"]
            .as_str()
            .expect("HTTP-admitted run ID")
            .to_owned();
        observer.session_id = Some(session_id.clone());
        observer.attach(&run_id).await;
        (observer, run_id, session_id)
    }

    async fn attach(&mut self, run_id: &str) {
        let stream = TcpStream::connect(self.address)
            .await
            .expect("connect owned gateway");
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .expect("local HTTP handshake");
        self.connection = Some(tokio::spawn(connection));
        let path = format!("/v1/runs/{run_id}/events");
        let response = sender
            .send_request(
                Request::builder()
                    .uri(&path)
                    .header("host", self.address.to_string())
                    .header("authorization", format!("Bearer {LOCAL_BEARER}"))
                    .body(Empty::<bytes::Bytes>::new())
                    .unwrap(),
            )
            .await
            .expect("live SSE response head");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/event-stream")
        );
        self.http_trace.push(
            json!({"method":"GET","path":path,"status":200,"content_type":"text/event-stream"}),
        );
        self.collector = Some(tokio::spawn(async move {
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.expect("gateway SSE delivery frame");
                if let Some(data) = frame.data_ref() {
                    assert!(bytes.len().saturating_add(data.len()) <= MAX_DELIVERY_BYTES);
                    bytes.extend_from_slice(data);
                }
            }
            drop(sender);
            bytes
        }));
    }

    pub async fn finish(mut self) -> Receipt {
        let bytes = tokio::time::timeout(Duration::from_secs(620), self.collector.take().unwrap())
            .await
            .expect("delivery stream must terminate")
            .expect("delivery collector join");
        if let Some(session_id) = self.session_id.clone() {
            assert_eq!(
                self.request_json(
                    "GET",
                    &format!("/api/sessions/{session_id}"),
                    Value::Null,
                    true
                )
                .await
                .0,
                200
            );
            assert_eq!(
                self.request_json(
                    "GET",
                    &format!("/api/sessions/{session_id}/messages"),
                    Value::Null,
                    true
                )
                .await
                .0,
                200
            );
        }
        let connection = self.connection.take().unwrap();
        connection.abort();
        let _ = connection.await;
        let _ = self.shutdown.take().unwrap().send(());
        tokio::time::timeout(Duration::from_secs(3), self.server.take().unwrap())
            .await
            .expect("gateway shutdown deadline")
            .expect("gateway join")
            .expect("gateway shutdown");
        let listener_closed =
            tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(self.address))
                .await
                .is_ok_and(|result| result.is_err());
        assert!(listener_closed, "owned gateway listener must close");
        let wire = String::from_utf8(bytes).expect("UTF-8 gateway SSE");
        let events: Vec<Value> = wire
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(|data| serde_json::from_str(data.trim()).expect("actual delivered event JSON"))
            .collect();
        Receipt {
            wire,
            events,
            listener_closed,
            http_trace: std::mem::take(&mut self.http_trace),
        }
    }
}
impl Drop for Observer {
    fn drop(&mut self) {
        if let Some(task) = self.collector.take() {
            task.abort();
        }
        if let Some(task) = self.connection.take() {
            task.abort();
        }
        if let Some(signal) = self.shutdown.take() {
            let _ = signal.send(());
        }
        if let Some(task) = self.server.take() {
            task.abort();
        }
    }
}
