//! Native Telegram Bot API transport: typed client, long-poll updates, and
//! bounded retry policy.
//!
//! The client speaks the Bot API over the existing dependency graph (hyper +
//! hyper-util, already pulled by axum). Transport security: the default
//! `https://api.telegram.org` base is served by a rustls TLS connector (the
//! pinned pd-vm already locks rustls/tokio-rustls/webpki-roots, so this adds
//! no new transitive crates); a plain `http` base is rejected by
//! configuration unless it is a localhost test escape hatch (see
//! [`crate::config::TelegramConfig::allow_insecure_localhost`]). The bot
//! token is embedded in the request URL by Telegram's protocol, so the URL is
//! never logged and the token never appears in `Debug` output; only the
//! method name and the typed outcome are observable.
//!
//! Retry policy (bounded): HTTP 429 sleeps `retry_after` (capped at
//! `max_429_backoff`) for at most `max_429_retries`; HTTP 5xx retries at most
//! `max_5xx_retries` times with capped exponential backoff; any other 4xx is
//! a typed `Api` failure with no retry; transport failures are typed and
//! surfaced immediately (the poller treats them as recoverable). No retry
//! path is unbounded. Response bodies are collected under a configured byte
//! cap and a body that exceeds it is a typed `ResponseTooLarge` failure.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::Request as HyperRequest;
use hyper::Uri;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::timeout;
use tower::Service;

use crate::config::TelegramConfig;

/// One `getUpdates` result item.
#[derive(Clone, Debug, Deserialize)]
pub struct TgUpdate {
    pub update_id: i64,
    pub message: Option<TgMessage>,
}

/// One Bot API message.
#[derive(Clone, Debug, Deserialize)]
pub struct TgMessage {
    pub message_id: i64,
    pub date: i64,
    pub chat: TgChat,
    pub from: Option<TgUser>,
    pub text: Option<String>,
    pub message_thread_id: Option<i64>,
    pub is_topic_message: Option<bool>,
}

/// One Bot API chat.
#[derive(Clone, Debug, Deserialize)]
pub struct TgChat {
    pub id: i64,
    #[serde(rename = "type")]
    pub chat_type: String,
    pub title: Option<String>,
}

/// One Bot API user.
#[derive(Clone, Debug, Deserialize)]
pub struct TgUser {
    pub id: i64,
    pub is_bot: bool,
    pub first_name: Option<String>,
    pub username: Option<String>,
}

/// One `sendMessage`/`editMessageText` result (the message that was sent).
#[derive(Clone, Debug, Deserialize)]
pub struct TgSentMessage {
    pub message_id: i64,
}

/// Typed Bot API failure. `RateLimited` carries the server's `retry_after`
/// hint; `Server` is an HTTP 5xx after the bounded retry budget; `Api` is any
/// other 4xx/API-level error (never retried); `Transport` is a network or
/// timeout failure; `ResponseTooLarge` is a response body beyond the
/// configured `max_response_body_bytes` cap (never buffered).
#[derive(Debug, Clone, PartialEq)]
pub enum TelegramError {
    Api {
        error_code: i64,
        description: String,
    },
    RateLimited {
        retry_after: u64,
    },
    Server {
        status: u16,
    },
    Transport(String),
    ResponseTooLarge {
        limit: u64,
    },
}

impl std::fmt::Display for TelegramError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api {
                error_code,
                description,
            } => write!(formatter, "Telegram API error {error_code}: {description}"),
            Self::RateLimited { retry_after } => {
                write!(
                    formatter,
                    "Telegram rate limited; retry after {retry_after}s"
                )
            }
            Self::Server { status } => write!(formatter, "Telegram server error (HTTP {status})"),
            Self::Transport(message) => write!(formatter, "Telegram transport error: {message}"),
            Self::ResponseTooLarge { limit } => write!(
                formatter,
                "Telegram response body exceeds the {limit}-byte cap"
            ),
        }
    }
}

impl std::error::Error for TelegramError {}

/// The Bot API envelope; `ok:false` carries the typed error fields.
#[derive(Deserialize)]
struct ApiEnvelope<T> {
    ok: bool,
    result: Option<T>,
    error_code: Option<i64>,
    description: Option<String>,
    parameters: Option<ApiParameters>,
}

#[derive(Deserialize)]
struct ApiParameters {
    retry_after: Option<u64>,
}

/// One Bot API connection: a plain TCP stream for `http` or a rustls TLS
/// stream for `https`. The connector routes by URI scheme, so an `https://`
/// api_base is always wrapped in TLS and never handed to the plain-text
/// path (and vice versa: `http` never goes through TLS). The enum
/// implements both the tokio I/O traits (for rustls) and hyper's runtime
/// I/O traits (for the hyper-util legacy client).
enum TelegramConnStream {
    Http(tokio::net::TcpStream),
    Https(tokio_rustls::client::TlsStream<tokio::net::TcpStream>),
}

impl TelegramConnStream {
    fn poll_read_tokio(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Http(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Https(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncRead for TelegramConnStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_read_tokio(cx, buf)
    }
}

impl AsyncWrite for TelegramConnStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Http(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Https(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Http(stream) => Pin::new(stream).poll_flush(cx),
            Self::Https(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Http(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Https(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Http(stream) => stream.is_write_vectored(),
            Self::Https(stream) => stream.is_write_vectored(),
        }
    }
}

impl hyper::rt::Read for TelegramConnStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        // Adapt the hyper read buffer to a tokio ReadBuf, exactly like
        // hyper-util's TokioIo does, then delegate to the tokio I/O impl.
        let filled = unsafe {
            let mut tbuf = tokio::io::ReadBuf::uninit(buf.as_mut());
            match self.poll_read_tokio(cx, &mut tbuf) {
                Poll::Ready(Ok(())) => tbuf.filled().len(),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        };
        // SAFETY: the filled bytes were initialized by the read above.
        unsafe { buf.advance(filled) };
        Poll::Ready(Ok(()))
    }
}

impl hyper::rt::Write for TelegramConnStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(self, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(self, cx)
    }
}

impl Connection for TelegramConnStream {
    fn connected(&self) -> Connected {
        match self {
            Self::Http(stream) => stream.connected(),
            Self::Https(stream) => stream.get_ref().0.connected(),
        }
    }
}

/// Scheme-routing connector for the Bot API client. `https` URIs are
/// resolved through the plain connector to a TCP stream and then wrapped in
/// a rustls TLS session (webpki-roots anchors); `http` URIs stay plaintext.
#[derive(Clone)]
struct TelegramConnector {
    http: HttpConnector,
    tls: tokio_rustls::TlsConnector,
}

impl TelegramConnector {
    fn new() -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut http = HttpConnector::new();
        // hyper-util's plain connector is http-only by default; https URIs
        // must be accepted here and routed into the TLS layer below.
        http.enforce_http(false);
        Self {
            http,
            tls: tokio_rustls::TlsConnector::from(Arc::new(config)),
        }
    }
}

/// Maps a hyper-util connect error to an `io::Error`, preserving the
/// underlying error kind (connection refused, timeout, ...) when the source
/// chain exposes one. Generic so the private hyper-util error type is never
/// named.
fn map_connect_error<E>(error: E) -> io::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    let kind = std::error::Error::source(&error)
        .and_then(|cause| cause.downcast_ref::<io::Error>())
        .map(io::Error::kind)
        .unwrap_or(io::ErrorKind::Other);
    io::Error::new(kind, error)
}

impl Service<Uri> for TelegramConnector {
    type Response = TelegramConnStream;
    type Error = io::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        if uri.scheme_str() == Some("https") {
            let mut http = self.http.clone();
            let tls = self.tls.clone();
            Box::pin(async move {
                let tcp = http
                    .call(uri.clone())
                    .await
                    .map_err(map_connect_error)?
                    .into_inner();
                let host = uri.host().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "https URI has no host")
                })?;
                let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name")
                    })?;
                let tls_stream = tls.connect(server_name, tcp).await?;
                Ok(TelegramConnStream::Https(tls_stream))
            })
        } else {
            let mut http = self.http.clone();
            Box::pin(async move {
                http.call(uri)
                    .await
                    .map(|stream| TelegramConnStream::Http(stream.into_inner()))
                    .map_err(map_connect_error)
            })
        }
    }
}

/// The minimal HTTP client surface the Bot API needs; the token lives only
/// inside the per-request URL and in this struct (redacted `Debug`).
pub struct TelegramApi {
    api_base: String,
    token: String,
    client: Client<TelegramConnector, Full<Bytes>>,
    request_timeout: Duration,
    max_429_retries: usize,
    max_429_backoff: Duration,
    max_5xx_retries: usize,
    max_response_body_bytes: u64,
}

impl std::fmt::Debug for TelegramApi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TelegramApi")
            .field("api_base", &self.api_base)
            .field("token", &"REDACTED")
            .field("request_timeout", &self.request_timeout)
            .field("max_429_retries", &self.max_429_retries)
            .field("max_429_backoff", &self.max_429_backoff)
            .field("max_5xx_retries", &self.max_5xx_retries)
            .field("max_response_body_bytes", &self.max_response_body_bytes)
            .finish()
    }
}

impl TelegramApi {
    /// Builds the client from validated configuration. The request timeout
    /// always exceeds the long-poll timeout so a poll round is never cut
    /// short by the client itself.
    pub fn new(config: &TelegramConfig) -> Self {
        let connector = TelegramConnector::new();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Self {
            api_base: config.api_base.trim_end_matches('/').to_string(),
            token: config.bot_token.clone(),
            client,
            request_timeout: config.poll_timeout + Duration::from_secs(15),
            max_429_retries: config.max_429_retries,
            max_429_backoff: config.max_429_backoff,
            max_5xx_retries: config.max_5xx_retries,
            max_response_body_bytes: config.max_response_body_bytes as u64,
        }
    }

    /// Verifies the token and returns the bot account.
    pub async fn get_me(&self) -> Result<TgUser, TelegramError> {
        self.request("getMe", Value::Null).await
    }

    /// Long-polls for updates at `offset` (the next update_id to fetch) with
    /// the given timeout; only `message` updates are requested.
    pub async fn get_updates(
        &self,
        offset: Option<i64>,
        timeout_secs: u64,
        limit: u64,
    ) -> Result<Vec<TgUpdate>, TelegramError> {
        let mut params = serde_json::Map::new();
        if let Some(offset) = offset {
            params.insert("offset".to_string(), json!(offset));
        }
        params.insert("timeout".to_string(), json!(timeout_secs));
        params.insert("limit".to_string(), json!(limit));
        params.insert("allowed_updates".to_string(), json!(["message"]));
        self.request("getUpdates", Value::Object(params)).await
    }

    /// Sends one plain-text message; `thread_id` targets a forum topic.
    pub async fn send_message(
        &self,
        chat_id: i64,
        thread_id: Option<i64>,
        text: &str,
    ) -> Result<TgSentMessage, TelegramError> {
        let mut params = serde_json::Map::new();
        params.insert("chat_id".to_string(), json!(chat_id));
        if let Some(thread_id) = thread_id {
            params.insert("message_thread_id".to_string(), json!(thread_id));
        }
        params.insert("text".to_string(), json!(text));
        self.request("sendMessage", Value::Object(params)).await
    }

    /// Edits one previously sent message (delta delivery).
    pub async fn edit_message_text(
        &self,
        chat_id: i64,
        message_id: i64,
        text: &str,
    ) -> Result<TgSentMessage, TelegramError> {
        let mut params = serde_json::Map::new();
        params.insert("chat_id".to_string(), json!(chat_id));
        params.insert("message_id".to_string(), json!(message_id));
        params.insert("text".to_string(), json!(text));
        self.request("editMessageText", Value::Object(params)).await
    }

    /// One typed call with the bounded retry policy (429/5xx budgets are
    /// independent and each bounded; everything else fails immediately).
    async fn request<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T, TelegramError> {
        let mut remaining_429 = self.max_429_retries;
        let mut remaining_5xx = self.max_5xx_retries;
        loop {
            match self.request_once(method, &params).await {
                Ok(value) => return Ok(value),
                Err(TelegramError::RateLimited { retry_after }) if remaining_429 > 0 => {
                    remaining_429 -= 1;
                    let delay = self
                        .max_429_backoff
                        .min(Duration::from_secs(retry_after.max(1)));
                    tokio::time::sleep(delay).await;
                }
                Err(TelegramError::Server { .. }) if remaining_5xx > 0 => {
                    remaining_5xx -= 1;
                    // Capped exponential backoff: 250ms, 500ms, 1s, ...
                    let attempt = self.max_5xx_retries - remaining_5xx;
                    let delay = Duration::from_millis(250 * (1_u64 << attempt.min(4)));
                    tokio::time::sleep(delay).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// One unretried HTTP round trip.
    async fn request_once<T: DeserializeOwned>(
        &self,
        method: &str,
        params: &Value,
    ) -> Result<T, TelegramError> {
        // The token is part of the URL by Bot API protocol; the URL is never
        // logged or formatted into any error message.
        let url = format!("{}/bot{}/{}", self.api_base, self.token, method);
        let body = if params.is_null() {
            Bytes::new()
        } else {
            Bytes::from(serde_json::to_string(params).unwrap_or_else(|_| "{}".to_string()))
        };
        let request = HyperRequest::builder()
            .method("POST")
            .uri(&url)
            .header("content-type", "application/json")
            .body(Full::new(body))
            .map_err(|error| TelegramError::Transport(format!("build Bot API request: {error}")))?;
        let response = timeout(self.request_timeout, self.client.request(request))
            .await
            .map_err(|_| TelegramError::Transport("Bot API request timed out".to_string()))?
            .map_err(|error| {
                // Include the cause chain (for example the TLS handshake
                // reason) without ever formatting the request URL, which
                // carries the token.
                let mut message = format!("Bot API request failed: {error}");
                let mut source = std::error::Error::source(&error);
                while let Some(cause) = source {
                    message.push_str(&format!(": {cause}"));
                    source = cause.source();
                }
                TelegramError::Transport(message)
            })?;
        let status = response.status();
        // Collect the body under the configured cap: a body that exceeds it
        // (declared Content-Length or streamed chunks) aborts immediately
        // with a typed over-limit failure and is never buffered whole.
        let limited = http_body_util::Limited::new(
            response.into_body(),
            self.max_response_body_bytes as usize,
        );
        let bytes = timeout(
            self.request_timeout,
            http_body_util::BodyExt::collect(limited),
        )
        .await
        .map_err(|_| TelegramError::Transport("Bot API response timed out".to_string()))?
        .map_err(|error| {
            if error
                .downcast_ref::<http_body_util::LengthLimitError>()
                .is_some()
            {
                TelegramError::ResponseTooLarge {
                    limit: self.max_response_body_bytes,
                }
            } else {
                TelegramError::Transport(format!("read Bot API response: {error}"))
            }
        })?
        .to_bytes();
        if status == hyper::StatusCode::TOO_MANY_REQUESTS {
            // Prefer the body's retry_after hint; fall back to the header or 1.
            let retry_after = serde_json::from_slice::<ApiEnvelope<Value>>(&bytes)
                .ok()
                .and_then(|envelope| envelope.parameters)
                .and_then(|parameters| parameters.retry_after)
                .unwrap_or(1);
            return Err(TelegramError::RateLimited { retry_after });
        }
        if status.is_server_error() {
            return Err(TelegramError::Server {
                status: status.as_u16(),
            });
        }
        let envelope: ApiEnvelope<T> = serde_json::from_slice(&bytes).map_err(|error| {
            TelegramError::Transport(format!(
                "invalid Bot API response (HTTP {}): {error}",
                status.as_u16()
            ))
        })?;
        if envelope.ok {
            envelope.result.ok_or_else(|| {
                TelegramError::Transport("Bot API response omitted the result".to_string())
            })
        } else {
            match envelope.error_code {
                Some(429) => Err(TelegramError::RateLimited {
                    retry_after: envelope
                        .parameters
                        .and_then(|parameters| parameters.retry_after)
                        .unwrap_or(1),
                }),
                Some(error_code) => Err(TelegramError::Api {
                    error_code,
                    description: envelope.description.unwrap_or_default(),
                }),
                None => Err(TelegramError::Transport(
                    "Bot API error response omitted error_code".to_string(),
                )),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Adapter: allowlists, envelope mapping, polling, commands, and delivery.
// ---------------------------------------------------------------------------

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::{broadcast, watch};

use crate::AgentGatewayState;
use crate::domain::{InboundEnvelope, fnv1a64, timestamp};
use crate::gateway::store::{GatewayEvent, SessionRecord, SessionView};
use crate::gateway::telegram_render::{EventRenderer, RenderAction};
use crate::service::{AdmitError, AdmitRunRequest, failed_payload};

/// Delivery cursor consumer for the global getUpdates offset (hangs on the
/// control session).
pub(crate) const OFFSET_CONSUMER: &str = "telegram:offset";

/// Canonical session id for one (account, chat, thread) identity. Stable
/// across restarts; `/new` wipes and recreates the same id.
pub(crate) fn session_id_for(account: &str, chat_id: i64, thread_id: Option<i64>) -> String {
    let thread = thread_id.map(|id| id.to_string()).unwrap_or_default();
    format!("telegram:{account}:{chat_id}:{thread}")
}

/// The bot-owned control session that anchors transport-level cursors (the
/// getUpdates offset).
pub(crate) fn control_session_id(account: &str) -> String {
    format!("telegram-control:{account}")
}

/// Per-run delivery cursor consumer.
pub(crate) fn run_consumer(run_id: &str) -> String {
    format!("telegram:run:{run_id}")
}

/// Deny-by-default allowlists: every list starts empty and an empty list
/// denies everything.
struct Allowlist {
    accounts: Vec<String>,
    chats: Vec<i64>,
    users: Vec<i64>,
}

impl Allowlist {
    fn from_config(config: &TelegramConfig) -> Self {
        Self {
            accounts: config
                .allowed_accounts
                .iter()
                .map(|account| account.to_ascii_lowercase())
                .collect(),
            chats: config.allowed_chats.clone(),
            users: config.allowed_users.clone(),
        }
    }

    fn account_allowed(&self, username: &str) -> bool {
        self.accounts
            .iter()
            .any(|allowed| allowed == &username.to_ascii_lowercase())
    }

    fn chat_allowed(&self, chat_id: i64) -> bool {
        self.chats.contains(&chat_id)
    }

    fn user_allowed(&self, user_id: i64) -> bool {
        self.users.contains(&user_id)
    }
}

/// Bounded dedup windows for update_ids and (chat, message) keys; old
/// entries fall off so the memory footprint stays fixed.
struct DedupWindows {
    update_ids: VecDeque<i64>,
    message_keys: VecDeque<String>,
    capacity: usize,
}

impl DedupWindows {
    fn new(capacity: usize) -> Self {
        Self {
            update_ids: VecDeque::new(),
            message_keys: VecDeque::new(),
            capacity,
        }
    }

    /// Returns true when the update_id was already seen.
    fn seen_update(&mut self, update_id: i64) -> bool {
        if self.update_ids.contains(&update_id) {
            return true;
        }
        push_bounded(&mut self.update_ids, update_id, self.capacity);
        false
    }

    /// Returns true when the (chat, message) key was already seen.
    fn seen_message(&mut self, key: &str) -> bool {
        if self.message_keys.iter().any(|existing| existing == key) {
            return true;
        }
        push_bounded(&mut self.message_keys, key.to_string(), self.capacity);
        false
    }
}

fn push_bounded<T>(window: &mut VecDeque<T>, value: T, capacity: usize) {
    if window.len() >= capacity {
        window.pop_front();
    }
    window.push_back(value);
}

/// Parses one message text into a known command and its remaining content.
/// Only the four canonical commands are recognized; anything else (including
/// unknown `/x` tokens) is plain conversation text.
pub(crate) fn parse_command(text: &str) -> (Option<String>, String) {
    let trimmed = text.trim();
    if let Some(rest) = trimmed.strip_prefix('/') {
        let mut parts = rest.splitn(2, char::is_whitespace);
        let token = parts.next().unwrap_or_default();
        let args = parts.next().unwrap_or("").trim();
        let name = token
            .split('@')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if matches!(name.as_str(), "new" | "stop" | "status" | "compact") {
            return (Some(name), args.to_string());
        }
    }
    (None, trimmed.to_string())
}

/// Normalizes one Telegram message into the canonical inbound envelope.
/// Non-text messages and messages without a sender are not user input.
pub(crate) fn envelope_from_message(
    update: &TgUpdate,
    message: &TgMessage,
    account: &str,
) -> Option<InboundEnvelope> {
    let from = message.from.as_ref()?;
    let content = message.text.clone().unwrap_or_default();
    if content.trim().is_empty() {
        return None;
    }
    // Private chats have no thread; group/supergroup topics are identified
    // by message_thread_id (the General topic has none). The identity is
    // stable because both dimensions come straight from the platform.
    let thread_id = match message.chat.chat_type.as_str() {
        "private" => None,
        _ => message.message_thread_id,
    };
    let (command, content) = parse_command(&content);
    Some(InboundEnvelope {
        platform: "telegram".to_string(),
        profile: "telegram".to_string(),
        account_id: account.to_string(),
        chat_id: message.chat.id.to_string(),
        thread_id: thread_id.map(|id| id.to_string()),
        user_id: from.id.to_string(),
        message_id: format!("{}:{}", message.chat.id, message.message_id),
        session_hint: None,
        content,
        attachments: Vec::new(),
        command,
        reply_to: None,
        received_at: timestamp(),
        metadata: json!({
            "update_id": update.update_id,
            "message_id": message.message_id,
            "chat_type": message.chat.chat_type,
            "is_topic_message": message.is_topic_message,
        }),
    })
}

/// Shared adapter runtime: the gateway state, the allowlist, the bounded
/// dedup windows, and the per-session active-run gate.
struct AdapterRuntime {
    state: AgentGatewayState,
    config: TelegramConfig,
    account: String,
    allowlist: Allowlist,
    dedup: DedupWindows,
    active_runs: Arc<Mutex<HashMap<String, String>>>,
    /// Per-session reset epochs: a renderer captures the epoch at spawn and
    /// aborts once `/new` bumps it, so an old renderer can never output
    /// into a recreated session.
    epochs: Arc<Mutex<HashMap<String, u64>>>,
    /// Metric: delivery cursor advance failures (at-least-once delivery
    /// hook — see [`advance_cursor`]).
    advance_failures: Arc<AtomicU64>,
}

/// Handle for one running Telegram adapter (poller task). Shutdown is
/// bounded: the stop signal is sent, the in-flight poll round finishes
/// within the client timeout, the final offset is persisted, and the join
/// waits at most the configured bound.
pub struct TelegramAdapter {
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    processed: Arc<AtomicU64>,
    advance_failures: Arc<AtomicU64>,
}

impl TelegramAdapter {
    /// Number of updates fully handled so far (tests poll this).
    pub fn processed_updates(&self) -> u64 {
        self.processed.load(Ordering::SeqCst)
    }

    /// Metric: delivery cursor advance failures (at-least-once delivery).
    pub fn advance_failure_count(&self) -> u64 {
        self.advance_failures.load(Ordering::SeqCst)
    }

    /// Bounded graceful stop: signals the poller, waits at most 60s for the
    /// in-flight poll round and the final offset persist.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(60), self.task).await;
    }
}

/// Starts the Telegram adapter: verifies the token via `getMe`, ensures the
/// control session, loads the persisted poll offset, and spawns the long
/// poll loop. The adapter shares the gateway's AgentService/store, so API
/// and Telegram traffic use the same sessions and runs.
pub async fn spawn_telegram_adapter(
    state: AgentGatewayState,
    config: TelegramConfig,
) -> Result<TelegramAdapter, String> {
    config
        .validate()
        .map_err(|error| format!("invalid Telegram configuration: {error}"))?;
    let api = TelegramApi::new(&config);
    let me = api
        .get_me()
        .await
        .map_err(|error| format!("telegram getMe failed: {error}"))?;
    let account = me
        .username
        .clone()
        .unwrap_or_else(|| format!("bot{}", me.id));
    ensure_control_session(&state, &account, me.id).await?;
    let offset = load_offset(&state, &account).await?;
    let (stop_tx, stop_rx) = watch::channel(false);
    let processed = Arc::new(AtomicU64::new(0));
    let advance_failures = Arc::new(AtomicU64::new(0));
    let task = tokio::spawn(run_poller(
        state,
        config,
        account,
        offset,
        stop_rx,
        Arc::clone(&processed),
        Arc::clone(&advance_failures),
    ));
    Ok(TelegramAdapter {
        stop: stop_tx,
        task,
        processed,
        advance_failures,
    })
}

/// Ensures the bot's control session exists (INSERT OR IGNORE semantics:
/// idempotent across restarts). It anchors the persisted getUpdates offset
/// cursor row.
async fn ensure_control_session(
    state: &AgentGatewayState,
    account: &str,
    bot_id: i64,
) -> Result<(), String> {
    let Some(persistence) = state.persistence() else {
        return Ok(());
    };
    let session_id = control_session_id(account);
    let model = state.config.model.clone();
    let account_for_block = account.to_string();
    let now = timestamp();
    let result = tokio::task::spawn_blocking(move || {
        let payload = json!({
            "id": session_id,
            "profile": "telegram",
            "platform": "telegram",
            "account_id": account_for_block,
            "chat_id": "",
            "thread_id": "",
            "user_id": bot_id.to_string(),
            "generation": 1,
            "system_prompt": "",
            "model": model,
            "provider": "",
            "toolset_hash": "",
            "metadata_json": "{}",
            "title": "telegram control",
            "end_reason": "",
            "now_ms": now as i64,
        });
        persistence.session_create(&payload).map(|_| ())
    })
    .await
    .map_err(|error| format!("control session worker failed: {error}"))?;
    result.map_err(|error| format!("create telegram control session: {error}"))
}

/// Loads the persisted getUpdates offset (0 when none was ever persisted).
async fn load_offset(state: &AgentGatewayState, account: &str) -> Result<Option<i64>, String> {
    let Some(persistence) = state.persistence() else {
        return Ok(None);
    };
    let data = persistence
        .delivery_get(&control_session_id(account), OFFSET_CONSUMER)
        .map_err(|error| format!("read telegram poll offset: {error}"))?;
    Ok(cursor_from_rows(&data))
}

/// Persists the getUpdates offset through the typed delivery cursor surface
/// (monotonic, so a stale process can never rewind the offset).
async fn persist_offset(
    state: &AgentGatewayState,
    account: &str,
    offset: i64,
) -> Result<(), String> {
    let Some(persistence) = state.persistence() else {
        return Ok(());
    };
    persistence
        .delivery_set(&control_session_id(account), OFFSET_CONSUMER, offset)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// The long-poll loop: getUpdates with offset management, bounded dedup,
/// allowlist gating, command/plain-text dispatch, and offset persistence
/// after every batch and on graceful stop.
async fn run_poller(
    state: AgentGatewayState,
    config: TelegramConfig,
    account: String,
    mut offset: Option<i64>,
    stop: watch::Receiver<bool>,
    processed: Arc<AtomicU64>,
    advance_failures: Arc<AtomicU64>,
) {
    let api = TelegramApi::new(&config);
    let mut runtime = AdapterRuntime {
        state: state.clone(),
        config: config.clone(),
        account: account.clone(),
        allowlist: Allowlist::from_config(&config),
        dedup: DedupWindows::new(config.dedup_capacity),
        active_runs: Arc::new(Mutex::new(HashMap::new())),
        epochs: Arc::new(Mutex::new(HashMap::new())),
        advance_failures,
    };
    let poll_timeout_secs = config.poll_timeout.as_secs().max(1);
    // Restart resume: after a crash the poll offset skips the interrupted
    // update, so its run exists only in durable state. Any event left
    // undelivered (delivery cursor < retained high-water) is rendered now.
    resume_undelivered(&mut runtime).await;
    // First boot without a persisted offset: by default drain pending
    // updates (queued while the bot was offline) without processing them,
    // so old updates are never replayed into sessions. Disable
    // drop_pending_updates to process them.
    if offset.is_none() && config.drop_pending_updates {
        drop_pending_updates(&api, &stop).await;
    }
    let mut unauthorized_streak = 0usize;
    loop {
        if *stop.borrow() {
            break;
        }
        match api.get_updates(offset, poll_timeout_secs, 50).await {
            Ok(updates) => {
                unauthorized_streak = 0;
                for update in updates {
                    if *stop.borrow() {
                        break;
                    }
                    if offset.is_some_and(|base| update.update_id < base) {
                        continue;
                    }
                    if runtime.dedup.seen_update(update.update_id) {
                        continue;
                    }
                    handle_update(&mut runtime, &api, &update).await;
                    processed.fetch_add(1, Ordering::SeqCst);
                    offset = Some(update.update_id + 1);
                }
                // Persist after every batch so a crash re-fetches at most the
                // last batch (message-level idempotency covers the rest).
                if let Err(error) = persist_offset(&state, &account, offset.unwrap_or(0)).await {
                    tracing::warn!("telegram poll offset could not be persisted: {error}");
                }
                // Pace poll rounds even when the fixture responds instantly;
                // the long poll itself already bounded the wait on real
                // Telegram, so this only prevents a hot loop.
                tokio::time::sleep(config.poll_interval).await;
            }
            Err(TelegramError::Api {
                error_code: 401, ..
            }) => {
                // Bounded circuit breaker: an unauthorized token will never
                // succeed, so stop polling instead of looping forever. The
                // API gateway keeps serving; the adapter is disabled for
                // this process.
                unauthorized_streak += 1;
                tracing::warn!(
                    "telegram adapter unauthorized (HTTP 401) {} consecutive failure(s); \
                     check the bot token",
                    unauthorized_streak
                );
                if unauthorized_streak >= config.unauthorized_failure_bound {
                    tracing::warn!(
                        "telegram adapter disabled after {} unauthorized failures",
                        unauthorized_streak
                    );
                    break;
                }
                tokio::time::sleep(config.poll_interval).await;
            }
            Err(TelegramError::Transport(error)) => {
                tracing::warn!("telegram poll transport failure: {error}");
                tokio::time::sleep(config.poll_interval).await;
            }
            Err(TelegramError::Server { status }) => {
                tracing::warn!("telegram poll server failure (HTTP {status})");
                tokio::time::sleep(config.poll_interval).await;
            }
            Err(error) => {
                tracing::warn!("telegram poll failed: {error}");
                tokio::time::sleep(config.poll_interval).await;
            }
        }
    }
    // Final persist on graceful stop: no update older than this offset can
    // be re-fetched after restart.
    if let Err(error) = persist_offset(&state, &account, offset.unwrap_or(0)).await {
        tracing::warn!("telegram poll offset could not be persisted on stop: {error}");
    }
}

/// Drains the pending-update queue on first boot without processing it
/// (bounded rounds; the offset advances past every drained update so they
/// are never re-fetched).
async fn drop_pending_updates(api: &TelegramApi, stop: &watch::Receiver<bool>) {
    let mut drain_offset = None;
    for _round in 0..100 {
        if *stop.borrow() {
            return;
        }
        match api.get_updates(drain_offset, 0, 50).await {
            Ok(updates) => {
                let Some(last) = updates.last() else {
                    return;
                };
                drain_offset = Some(last.update_id + 1);
            }
            Err(error) => {
                tracing::warn!("telegram pending-update drain failed: {error}");
                return;
            }
        }
    }
    tracing::warn!("telegram pending-update drain hit its round bound");
}

/// The poller's per-session active-run gate with RAII release: the entry is
/// removed on every exit path, including a panicking renderer task.
struct GateGuard {
    active_runs: Arc<Mutex<HashMap<String, String>>>,
    session_id: String,
}

impl Drop for GateGuard {
    fn drop(&mut self) {
        self.active_runs
            .lock()
            .expect("active runs lock")
            .remove(&self.session_id);
    }
}

/// Parses the canonical telegram session id back into chat/thread identity
/// (`telegram:<account>:<chat>:<thread>`); `None` for non-telegram ids (for
/// example the bot's control session).
fn parse_session_identity(session_id: &str) -> Option<(i64, Option<i64>)> {
    let rest = session_id.strip_prefix("telegram:")?;
    let mut parts = rest.splitn(3, ':');
    let _account = parts.next()?;
    let chat_id = parts.next()?.parse::<i64>().ok()?;
    let thread = parts.next().unwrap_or("");
    let thread_id = if thread.is_empty() {
        None
    } else {
        Some(thread.parse::<i64>().ok()?)
    };
    Some((chat_id, thread_id))
}

/// Renders any events left undelivered before the previous process stopped:
/// for every telegram session, every run whose delivery cursor trails its
/// retained high-water gets a fresh renderer (the live path would never
/// touch it again, and restart must not lose output).
async fn resume_undelivered(runtime: &mut AdapterRuntime) {
    let sessions = {
        let store = runtime.state.store.read();
        store
            .sessions
            .values()
            .filter(|session| session.view.source == "telegram")
            .filter_map(|session| {
                let identity = parse_session_identity(&session.view.id)?;
                Some((session.view.id.clone(), identity.0, identity.1))
            })
            .collect::<Vec<_>>()
    };
    for (session_id, chat_id, thread_id) in sessions {
        let runs = {
            let store = runtime.state.store.read();
            store
                .runs
                .values()
                .filter(|run| run.session_id == session_id)
                .map(|run| run.run_id.clone())
                .collect::<Vec<_>>()
        };
        for run_id in runs {
            let consumer = run_consumer(&run_id);
            let cursor = load_cursor(&runtime.state, &session_id, &consumer).await;
            let high_water = {
                let store = runtime.state.store.read();
                store
                    .runs
                    .get(&run_id)
                    .map(|run| run.events.iter().map(|event| event.seq).max().unwrap_or(0) as i64)
                    .unwrap_or(0)
            };
            if high_water > cursor {
                runtime
                    .active_runs
                    .lock()
                    .expect("active runs lock")
                    .insert(session_id.clone(), run_id.clone());
                spawn_run_renderer(
                    &runtime.state,
                    &runtime.config,
                    &session_id,
                    run_id,
                    chat_id,
                    thread_id,
                    Arc::clone(&runtime.active_runs),
                    Arc::clone(&runtime.epochs),
                    Arc::clone(&runtime.advance_failures),
                );
            }
        }
    }
}

/// One update: envelope, allowlist gates, dedup, then command or admission.
async fn handle_update(runtime: &mut AdapterRuntime, api: &TelegramApi, update: &TgUpdate) {
    let Some(message) = &update.message else {
        return;
    };
    let Some(envelope) = envelope_from_message(update, message, &runtime.account) else {
        return;
    };
    // Deny-by-default allowlists; denied updates are dropped silently (the
    // offset still advances, so they are not re-fetched forever).
    if !runtime.allowlist.account_allowed(&runtime.account) {
        tracing::debug!("telegram account not allowed; update dropped");
        return;
    }
    let chat_id = message.chat.id;
    if !runtime.allowlist.chat_allowed(chat_id) {
        tracing::debug!(chat_id, "telegram chat not allowed; update dropped");
        return;
    }
    let Some(from) = &message.from else {
        return;
    };
    if !runtime.allowlist.user_allowed(from.id) {
        tracing::debug!(
            user_id = from.id,
            "telegram user not allowed; update dropped"
        );
        return;
    }
    let message_key = format!("{}:{}", chat_id, message.message_id);
    if runtime.dedup.seen_message(&message_key) {
        return;
    }
    let session_id = session_id_for(&runtime.account, chat_id, message.message_thread_id);
    match envelope.command.as_deref() {
        Some("new") => {
            cmd_new(
                runtime,
                api,
                &envelope,
                chat_id,
                message.message_thread_id,
                &session_id,
            )
            .await
        }
        Some("stop") => {
            cmd_stop(
                runtime,
                api,
                chat_id,
                message.message_thread_id,
                &session_id,
            )
            .await
        }
        Some("status") => {
            cmd_status(
                runtime,
                api,
                chat_id,
                message.message_thread_id,
                &session_id,
            )
            .await
        }
        Some("compact") => {
            // Explicitly unavailable: compaction is A5-scoped and not wired
            // here; never advertise it as complete.
            let _ = reply(
                api,
                chat_id,
                message.message_thread_id,
                "/compact is not available yet: compaction is blocked until the A5 integration lands; \
                 your conversation is unchanged.",
            )
            .await;
        }
        _ => {
            admit_text(
                runtime,
                api,
                &envelope,
                &session_id,
                chat_id,
                message.message_thread_id,
            )
            .await
        }
    }
}

/// One bounded plain-text reply to the chat (thread-aware).
async fn reply(
    api: &TelegramApi,
    chat_id: i64,
    thread_id: Option<i64>,
    text: &str,
) -> Result<(), TelegramError> {
    api.send_message(chat_id, thread_id, text).await.map(|_| ())
}

/// The session's active run for command targeting (`/stop`, `/new`): the
/// gated run wins; a gate-less fallback scans the store for started/stopping
/// runs and picks the most recently active one (deterministic restart
/// recovery path — terminal runs never qualify).
fn session_active_run(
    active_runs: &Arc<Mutex<HashMap<String, String>>>,
    store: &crate::gateway::store::GatewayStore,
    session_id: &str,
) -> Option<String> {
    if let Some(run_id) = active_runs
        .lock()
        .expect("active runs lock")
        .get(session_id)
    {
        return Some(run_id.clone());
    }
    store
        .runs
        .values()
        .filter(|run| run.session_id == session_id)
        .filter(|run| matches!(run.status.as_str(), "started" | "stopping"))
        .max_by_key(|run| run.events.last().map(|event| event.timestamp).unwrap_or(0))
        .map(|run| run.run_id.clone())
}

/// `/new`: wipes the conversation (typed cascade delete) and recreates the
/// same deterministic session id, so the identity stays stable across
/// restarts while the history starts fresh.
async fn cmd_new(
    runtime: &AdapterRuntime,
    api: &TelegramApi,
    envelope: &InboundEnvelope,
    chat_id: i64,
    thread_id: Option<i64>,
    session_id: &str,
) {
    // 1. Typed cancel of the session's active run (if any), then a bounded
    //    wait for its terminal transition BEFORE anything is deleted. The
    //    session gate is held for the whole reset so no new run can be
    //    admitted mid-reset.
    let gated = runtime
        .active_runs
        .lock()
        .expect("active runs lock")
        .get(session_id)
        .cloned();
    let gate_was_held = gated.is_some();
    let run_id = gated.or_else(|| {
        // Restart fallback: the gate is in-memory, so scan the store for an
        // active run of the session (a run without a live service handle
        // reports None from stop() and the reset proceeds).
        let store = runtime.state.store.read();
        session_active_run(&runtime.active_runs, &store, session_id)
    });
    if let Some(run_id) = &run_id {
        runtime
            .active_runs
            .lock()
            .expect("active runs lock")
            .insert(session_id.to_string(), run_id.clone());
    }
    let mut stopped = true;
    if let Some(run_id) = run_id {
        match runtime.state.service().stop(&run_id).as_deref() {
            Some("stopping") | Some("started") => {
                let _ = reply(api, chat_id, thread_id, "Stopping the active run.").await;
                stopped =
                    wait_for_run_terminal(&runtime.state, &run_id, runtime.config.new_wait_timeout)
                        .await;
            }
            Some(_) => {
                // Already terminal (or stopping); nothing to wait for.
                stopped = true;
            }
            None => {
                // No live handle (for example a recovered run after a
                // restart): the durable run is not cancellable in this
                // process; the reset proceeds.
                stopped = true;
            }
        }
    }
    if !stopped {
        // Typed failure: the run did not reach terminal within the bound.
        // Nothing was deleted; the session and its run stay untouched and
        // the old renderer keeps delivering.
        let _ = reply(
            api,
            chat_id,
            thread_id,
            "Could not stop the active run; the conversation is unchanged. Try /stop and /new again.",
        )
        .await;
        if !gate_was_held {
            runtime
                .active_runs
                .lock()
                .expect("active runs lock")
                .remove(session_id);
        }
        return;
    }

    // 2. Invalidate any surviving old renderer: the epoch check aborts its
    //    in-flight output (including the final flush), so nothing from the
    //    old run can land in the recreated session.
    *runtime
        .epochs
        .lock()
        .expect("epochs lock")
        .entry(session_id.to_string())
        .or_insert(0) += 1;

    // 3. Cascade delete + recreate (same deterministic session id).
    let state = runtime.state.clone();
    let session_id_for_block = session_id.to_string();
    let account_for_block = envelope.account_id.clone();
    let user_id_for_block = envelope.user_id.clone();
    let chat_id_for_block = envelope.chat_id.clone();
    let thread_id_for_block = envelope.thread_id.clone().unwrap_or_default();
    let model = state.config.model.clone();
    let now = timestamp();
    let result = tokio::task::spawn_blocking(move || -> Result<(), String> {
        let mut store = state.store.write();
        let persistence = state.service.persistence_handle();
        // Only a session that exists is reset: on a fresh chat there is
        // nothing to cascade (session.delete on a missing session is a
        // typed error).
        if store.sessions.contains_key(&session_id_for_block) {
            // Mirror the durable cascade in memory: the session and its
            // runs go away together (the DB cascade removes
            // messages/events/cursors too).
            let removed_runs = store
                .runs
                .iter()
                .filter(|(_, run)| run.session_id == session_id_for_block)
                .map(|(run_id, _)| run_id.clone())
                .collect::<Vec<_>>();
            for run_id in removed_runs {
                store.runs.remove(&run_id);
            }
            if let Some(persistence) = persistence.as_ref() {
                persistence
                    .session_delete(&session_id_for_block)
                    .map_err(|error| error.to_string())?;
            }
            store.sessions.remove(&session_id_for_block);
        }
        if let Some(persistence) = persistence.as_ref() {
            let payload = json!({
                "id": session_id_for_block,
                "profile": "telegram",
                "platform": "telegram",
                "account_id": account_for_block,
                "chat_id": chat_id_for_block,
                "thread_id": thread_id_for_block,
                "user_id": user_id_for_block,
                "generation": 1,
                "system_prompt": "",
                "model": model,
                "provider": "",
                "toolset_hash": "",
                "metadata_json": "{}",
                "title": "",
                "end_reason": "",
                "now_ms": now as i64,
            });
            persistence
                .session_create(&payload)
                .map_err(|error| error.to_string())?;
        }
        store.sessions.insert(
            session_id_for_block.clone(),
            SessionRecord {
                view: SessionView {
                    id: session_id_for_block.clone(),
                    object: "hermes.session".to_string(),
                    title: None,
                    model,
                    provider: None,
                    source: "telegram".to_string(),
                    system_prompt: None,
                    created_at: now,
                    updated_at: now,
                    message_count: 0,
                    end_reason: None,
                },
                messages: Vec::new(),
            },
        );
        Ok(())
    })
    .await;
    // The recreated session starts with an empty gate.
    runtime
        .active_runs
        .lock()
        .expect("active runs lock")
        .remove(session_id);
    match result {
        Ok(Ok(())) => {
            let _ = reply(api, chat_id, thread_id, "New conversation started.").await;
        }
        _ => {
            let _ = reply(api, chat_id, thread_id, "Could not reset the conversation.").await;
        }
    }
}

/// Polls the in-memory store until the run reaches a terminal status (or
/// disappears), returning false when the bound expires first.
async fn wait_for_run_terminal(state: &AgentGatewayState, run_id: &str, bound: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + bound;
    loop {
        let terminal =
            state.store.read().runs.get(run_id).is_none_or(|run| {
                matches!(run.status.as_str(), "completed" | "failed" | "cancelled")
            });
        if terminal {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// `/stop`: cancels the session's active run through the shared
/// AgentService (the first stop wins; later stops report the status).
async fn cmd_stop(
    runtime: &AdapterRuntime,
    api: &TelegramApi,
    chat_id: i64,
    thread_id: Option<i64>,
    session_id: &str,
) {
    // The precise target is the session's active run: the gated run when
    // one is live, otherwise the most recently active started/stopping run
    // from the store (deterministic restart recovery; terminal runs never
    // qualify).
    let run_id = {
        let store = runtime.state.store.read();
        session_active_run(&runtime.active_runs, &store, session_id)
    };
    let outcome = match run_id {
        Some(run_id) => runtime.state.service().stop(&run_id),
        None => None,
    };
    match outcome.as_deref() {
        Some("stopping") => {
            let _ = reply(api, chat_id, thread_id, "Stopping the active run.").await;
        }
        Some(status) => {
            let _ = reply(api, chat_id, thread_id, &format!("Run status: {status}.")).await;
        }
        None => {
            let _ = reply(api, chat_id, thread_id, "No active run in this chat.").await;
        }
    }
}

/// `/status`: one readable line about the session and its latest run.
async fn cmd_status(
    runtime: &AdapterRuntime,
    api: &TelegramApi,
    chat_id: i64,
    thread_id: Option<i64>,
    session_id: &str,
) {
    let status_line = {
        let store = runtime.state.store.read();
        store.sessions.get(session_id).map(|session| {
            match store
                .runs
                .values()
                .filter(|run| run.session_id == session_id)
                .max_by_key(|run| run.events.last().map(|event| event.timestamp).unwrap_or(0))
            {
                Some(run) => format!(
                    "Session {session_id} · {} messages · latest run {}: {}",
                    session.view.message_count, run.run_id, run.status
                ),
                None => format!(
                    "Session {session_id} · {} messages · no runs yet",
                    session.view.message_count
                ),
            }
        })
    };
    let Some(status_line) = status_line else {
        let _ = reply(
            api,
            chat_id,
            thread_id,
            "No conversation yet in this chat — send a message to start one.",
        )
        .await;
        return;
    };
    let _ = reply(api, chat_id, thread_id, &status_line).await;
}

/// Ensures the deterministic session exists (durable + in-memory), so
/// admission can reference it. Idempotent: the typed `session.create` is
/// INSERT OR IGNORE and the in-memory map is checked first.
async fn ensure_session(
    state: &AgentGatewayState,
    session_id: &str,
    account: &str,
    chat_id: &str,
    thread_id: Option<&str>,
    user_id: &str,
) -> Result<(), String> {
    {
        let store = state.store.read();
        if store.sessions.contains_key(session_id) {
            return Ok(());
        }
    }
    let state_for_block = state.clone();
    let session_id_for_block = session_id.to_string();
    let account_for_block = account.to_string();
    let chat_id_for_block = chat_id.to_string();
    let thread_id_for_block = thread_id.unwrap_or_default().to_string();
    let user_id_for_block = user_id.to_string();
    let model = state.config.model.clone();
    let now = timestamp();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let mut store = state_for_block.store.write();
        if store.sessions.contains_key(&session_id_for_block) {
            return Ok(());
        }
        if let Some(persistence) = state_for_block.service.persistence_handle() {
            let payload = json!({
                "id": session_id_for_block,
                "profile": "telegram",
                "platform": "telegram",
                "account_id": account_for_block,
                "chat_id": chat_id_for_block,
                "thread_id": thread_id_for_block,
                "user_id": user_id_for_block,
                "generation": 1,
                "system_prompt": "",
                "model": model,
                "provider": "",
                "toolset_hash": "",
                "metadata_json": "{}",
                "title": "",
                "end_reason": "",
                "now_ms": now as i64,
            });
            persistence
                .session_create(&payload)
                .map_err(|error| error.to_string())?;
        }
        store.sessions.insert(
            session_id_for_block.clone(),
            SessionRecord {
                view: SessionView {
                    id: session_id_for_block.clone(),
                    object: "hermes.session".to_string(),
                    title: None,
                    model,
                    provider: None,
                    source: "telegram".to_string(),
                    system_prompt: None,
                    created_at: now,
                    updated_at: now,
                    message_count: 0,
                    end_reason: None,
                },
                messages: Vec::new(),
            },
        );
        Ok(())
    })
    .await
    .map_err(|error| format!("session worker failed: {error}"))?
}

/// Plain text: atomic admission through the shared AgentService with a
/// durable message-level idempotency key, so a re-fetched update after a
/// crash can never create a second run.
async fn admit_text(
    runtime: &AdapterRuntime,
    api: &TelegramApi,
    envelope: &InboundEnvelope,
    session_id: &str,
    chat_id: i64,
    thread_id: Option<i64>,
) {
    if runtime
        .active_runs
        .lock()
        .expect("active runs lock")
        .contains_key(session_id)
    {
        let _ = reply(
            api,
            chat_id,
            thread_id,
            "A run is already active in this chat — send /stop to cancel it.",
        )
        .await;
        return;
    }
    let canonical = serde_json::to_string(&json!({
        "input": envelope.content,
        "session_id": session_id,
    }))
    .unwrap_or_default();
    let idempotency_hash = format!("fnv64:{:016x}", fnv1a64(canonical.as_bytes()));
    let idempotency_key = format!(
        "telegram:{account}:{message}",
        account = envelope.account_id,
        message = envelope.message_id
    );
    if let Err(error) = ensure_session(
        &runtime.state,
        session_id,
        &envelope.account_id,
        &envelope.chat_id,
        envelope.thread_id.as_deref(),
        &envelope.user_id,
    )
    .await
    {
        tracing::warn!("telegram session creation failed: {error}");
        let _ = reply(
            api,
            chat_id,
            thread_id,
            "Storage is unavailable; try again shortly.",
        )
        .await;
        return;
    }
    let admitted = runtime
        .state
        .service()
        .admit(AdmitRunRequest {
            input: json!(envelope.content),
            session_id: Some(session_id.to_string()),
            platform: "telegram".to_string(),
            idempotency_key: Some(idempotency_key),
            idempotency_hash: Some(idempotency_hash),
            ..AdmitRunRequest::default()
        })
        .await;
    match admitted {
        Ok(admitted_run) => {
            if admitted_run.replayed {
                // The same message already produced this run (durable
                // idempotency across restarts); never start a second one.
                return;
            }
            runtime
                .active_runs
                .lock()
                .expect("active runs lock")
                .insert(session_id.to_string(), admitted_run.run_id.clone());
            spawn_worker(
                &runtime.state,
                admitted_run.run_id.clone(),
                envelope.content.clone(),
            );
            spawn_run_renderer(
                &runtime.state,
                &runtime.config,
                session_id,
                admitted_run.run_id,
                chat_id,
                thread_id,
                Arc::clone(&runtime.active_runs),
                Arc::clone(&runtime.epochs),
                Arc::clone(&runtime.advance_failures),
            );
        }
        Err(AdmitError::RunLimitReached) => {
            let _ = reply(
                api,
                chat_id,
                thread_id,
                "The agent is at capacity; try again shortly.",
            )
            .await;
        }
        Err(AdmitError::Persistence(message)) => {
            tracing::warn!("telegram admission persistence failure: {message}");
            let _ = reply(
                api,
                chat_id,
                thread_id,
                "Storage is unavailable; try again shortly.",
            )
            .await;
        }
        Err(error) => {
            let _ = reply(
                api,
                chat_id,
                thread_id,
                &format!("Could not start the run: {error}."),
            )
            .await;
        }
    }
}

/// Spawns the run worker with the same panic guard as the API server: a
/// worker that exits without a terminal commits a typed failure.
fn spawn_worker(state: &AgentGatewayState, run_id: String, input: String) {
    let service = state.service();
    let worker_run_id = run_id.clone();
    tokio::spawn(async move {
        let outcome =
            tokio::task::spawn(service.clone().run_worker(worker_run_id.clone(), input)).await;
        if outcome.is_err() {
            service
                .finish_failed(
                    &worker_run_id,
                    failed_payload("agent worker exited without a terminal outcome".to_string()),
                )
                .await;
        }
    });
}

/// Spawns the per-run delivery renderer: durable catch-up from the delivery
/// cursor, then live subscription, with the cursor advanced only after each
/// event was rendered successfully. The renderer captures the session's
/// current reset epoch and aborts all output once `/new` bumps it.
#[allow(clippy::too_many_arguments)]
fn spawn_run_renderer(
    state: &AgentGatewayState,
    config: &TelegramConfig,
    session_id: &str,
    run_id: String,
    chat_id: i64,
    thread_id: Option<i64>,
    active_runs: Arc<Mutex<HashMap<String, String>>>,
    epochs: Arc<Mutex<HashMap<String, u64>>>,
    advance_failures: Arc<AtomicU64>,
) {
    let state = state.clone();
    let config = config.clone();
    let session_id = session_id.to_string();
    let epoch = epochs
        .lock()
        .expect("epochs lock")
        .get(&session_id)
        .copied()
        .unwrap_or(0);
    tokio::spawn(run_renderer(
        state,
        config,
        session_id,
        run_id,
        chat_id,
        thread_id,
        active_runs,
        epochs,
        epoch,
        advance_failures,
    ));
}

/// One run's renderer: durable catch-up of undelivered retained events, then
/// live delivery through the run's broadcast channel. The live receiver is
/// attached BEFORE the catch-up replay, so no durable-before-visible event
/// can fall into a gap between the two paths; the delivery cursor (typed
/// `delivery.get`/`delivery.advance`) dedups both directions. The cursor is
/// advanced per event only after the Telegram API accepted the render, so
/// restart resumes exactly where delivery stopped. A terminal event ends
/// the renderer immediately (no live subscription is kept for a finished
/// run), which releases the session gate for the next admission.
async fn run_renderer(
    state: AgentGatewayState,
    config: TelegramConfig,
    session_id: String,
    run_id: String,
    chat_id: i64,
    thread_id: Option<i64>,
    active_runs: Arc<Mutex<HashMap<String, String>>>,
    epochs: Arc<Mutex<HashMap<String, u64>>>,
    epoch: u64,
    advance_failures: Arc<AtomicU64>,
) {
    let api = TelegramApi::new(&config);
    // RAII gate: released on every exit path, including panics.
    let _gate = GateGuard {
        active_runs,
        session_id: session_id.clone(),
    };
    let consumer = run_consumer(&run_id);
    let mut cursor = load_cursor(&state, &session_id, &consumer).await;
    let mut renderer = EventRenderer::new();
    let mut last_edit = Instant::now();

    // Attach the live receiver first: events broadcast while the replay
    // below runs are buffered here, and the cursor skips them afterwards.
    let receiver = subscribe_to_run(&state, &run_id);

    // Catch-up: every retained event with seq > cursor (bounded by event
    // retention) is rendered before any live event is considered.
    let events = replay_run_events(&state, &run_id, cursor + 1).await;
    for (seq, event_type, data) in events {
        if seq <= cursor {
            continue;
        }
        if !render_event(
            &api,
            &mut renderer,
            &mut last_edit,
            &config,
            chat_id,
            thread_id,
            seq,
            &event_type,
            &data,
            &mut cursor,
            &state,
            &session_id,
            &consumer,
            &epochs,
            epoch,
            &advance_failures,
        )
        .await
        {
            return;
        }
        if is_terminal_event_type(&event_type) {
            // The run is finished: render the final flush and end without
            // ever subscribing to a terminal run's channel (the gate is
            // released here).
            flush_renderer(
                &api,
                &mut renderer,
                chat_id,
                thread_id,
                &epochs,
                &session_id,
                epoch,
                &advance_failures,
            )
            .await;
            return;
        }
    }

    // Live: drain the receiver, skipping events already rendered by the
    // catch-up (seq <= cursor). A terminal event ends the loop.
    let mut receiver = match receiver {
        Some(receiver) => receiver,
        None => return,
    };
    loop {
        match receiver.recv().await {
            Ok(event) => {
                if (event.seq as i64) <= cursor {
                    if event.is_terminal() {
                        break;
                    }
                    continue;
                }
                if !render_event(
                    &api,
                    &mut renderer,
                    &mut last_edit,
                    &config,
                    chat_id,
                    thread_id,
                    event.seq as i64,
                    &event.event,
                    &event.data,
                    &mut cursor,
                    &state,
                    &session_id,
                    &consumer,
                    &epochs,
                    epoch,
                    &advance_failures,
                )
                .await
                {
                    break;
                }
                if event.is_terminal() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => {
                // The live buffer overflowed: re-sync from the durable
                // cursor, then re-subscribe.
                let current = load_cursor(&state, &session_id, &consumer).await;
                let events = replay_run_events(&state, &run_id, current + 1).await;
                let mut terminal = false;
                for (seq, event_type, data) in events {
                    if seq <= current {
                        continue;
                    }
                    if !render_event(
                        &api,
                        &mut renderer,
                        &mut last_edit,
                        &config,
                        chat_id,
                        thread_id,
                        seq,
                        &event_type,
                        &data,
                        &mut cursor,
                        &state,
                        &session_id,
                        &consumer,
                        &epochs,
                        epoch,
                        &advance_failures,
                    )
                    .await
                    {
                        terminal = true;
                        break;
                    }
                    if is_terminal_event_type(&event_type) {
                        terminal = true;
                        break;
                    }
                }
                if terminal {
                    break;
                }
                match subscribe_to_run(&state, &run_id) {
                    Some(next) => receiver = next,
                    None => break,
                }
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }

    // Final flush: any text accumulated but never edited is finalized.
    flush_renderer(
        &api,
        &mut renderer,
        chat_id,
        thread_id,
        &epochs,
        &session_id,
        epoch,
        &advance_failures,
    )
    .await;
}

/// Sends every pending render action once (the final flush after a terminal
/// event); a failed send stops the flush (the event stays undelivered for a
/// later catch-up). Aborts immediately when the session's reset epoch no
/// longer matches the renderer's captured epoch (the old run's output must
/// never reach a recreated session).
async fn flush_renderer(
    api: &TelegramApi,
    renderer: &mut EventRenderer,
    chat_id: i64,
    thread_id: Option<i64>,
    epochs: &Arc<Mutex<HashMap<String, u64>>>,
    session_id: &str,
    epoch: u64,
    _advance_failures: &Arc<AtomicU64>,
) {
    if !epoch_current(epochs, session_id, epoch) {
        return;
    }
    for action in renderer.flush() {
        let result = match action {
            RenderAction::Send { text } | RenderAction::SendDelta { text } => api
                .send_message(chat_id, thread_id, &text)
                .await
                .map(|_| ()),
            RenderAction::Edit { message_id, text } => api
                .edit_message_text(chat_id, message_id, &text)
                .await
                .map(|_| ()),
        };
        if result.is_err() {
            break;
        }
    }
}

/// True when the session's current reset epoch still matches the renderer's
/// captured epoch (false after `/new` bumped it). A session without any
/// entry is epoch 0, matching the renderer's capture default.
fn epoch_current(epochs: &Arc<Mutex<HashMap<String, u64>>>, session_id: &str, epoch: u64) -> bool {
    epochs
        .lock()
        .expect("epochs lock")
        .get(session_id)
        .copied()
        .unwrap_or(0)
        == epoch
}

/// True for the canonical terminal event types (replay rows carry only the
/// event type string, unlike live [`GatewayEvent`]s).
fn is_terminal_event_type(event_type: &str) -> bool {
    matches!(event_type, "run.completed" | "run.cancelled" | "run.failed")
}

/// Renders one canonical event into Bot API calls; the delivery cursor is
/// advanced only after every action succeeded. Returns false when delivery
/// failed (the event stays undelivered for a later catch-up) or when the
/// session's reset epoch no longer matches (old-run output must never reach
/// a recreated session).
#[allow(clippy::too_many_arguments)]
async fn render_event(
    api: &TelegramApi,
    renderer: &mut EventRenderer,
    last_edit: &mut Instant,
    config: &TelegramConfig,
    chat_id: i64,
    thread_id: Option<i64>,
    seq: i64,
    event_type: &str,
    data: &Value,
    cursor: &mut i64,
    state: &AgentGatewayState,
    session_id: &str,
    consumer: &str,
    epochs: &Arc<Mutex<HashMap<String, u64>>>,
    epoch: u64,
    advance_failures: &Arc<AtomicU64>,
) -> bool {
    if !epoch_current(epochs, session_id, epoch) {
        return false;
    }
    let throttle_edits = event_type == "model.delta";
    for action in renderer.on_event(event_type, data) {
        let result = match action {
            // Status lines never claim the delta edit target: only delta
            // sends report their reply id via note_sent.
            RenderAction::Send { text } => api
                .send_message(chat_id, thread_id, &text)
                .await
                .map(|_| ()),
            RenderAction::SendDelta { text } => {
                match api.send_message(chat_id, thread_id, &text).await {
                    Ok(sent) => {
                        renderer.note_sent(sent.message_id);
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            }
            RenderAction::Edit { message_id, text } => {
                if throttle_edits && last_edit.elapsed() < config.max_edit_interval {
                    // Throttled: the accumulated text stays in the renderer,
                    // so a later edit (or the final flush) re-sends it whole.
                    Ok(())
                } else {
                    match api.edit_message_text(chat_id, message_id, &text).await {
                        Ok(_) => {
                            *last_edit = Instant::now();
                            Ok(())
                        }
                        Err(error) => Err(error),
                    }
                }
            }
        };
        if let Err(error) = result {
            // The error text never contains the token (the client redacts
            // URLs and the token is not part of any error payload).
            tracing::warn!(event_type, "telegram delivery failed: {error}");
            return false;
        }
    }
    *cursor = seq;
    if let Err(error) = advance_cursor(state, session_id, consumer, seq).await {
        // At-least-once delivery: the render already reached Telegram, so
        // the event counts as delivered; the failed advance only means the
        // next catch-up re-renders it (a possible duplicate message). The
        // counter is the observable metric hook for this condition.
        advance_failures.fetch_add(1, Ordering::SeqCst);
        tracing::warn!("telegram delivery cursor advance failed: {error}");
    }
    true
}

/// Reads one delivery cursor row's `last_event_seq` (0 when absent).
fn cursor_from_rows(data: &Value) -> Option<i64> {
    data.get("rows")
        .and_then(Value::as_array)
        .and_then(|rows| rows.first())
        .and_then(|row| row.get(2))
        .and_then(Value::as_i64)
}

async fn load_cursor(state: &AgentGatewayState, session_id: &str, consumer: &str) -> i64 {
    let Some(persistence) = state.persistence() else {
        return 0;
    };
    match persistence.delivery_get(session_id, consumer) {
        Ok(data) => cursor_from_rows(&data).unwrap_or(0),
        Err(error) => {
            tracing::warn!("telegram delivery cursor read failed: {error}");
            0
        }
    }
}

/// Advances one delivery cursor. Delivery is at-least-once: the cursor is
/// advanced only after the Telegram API accepted the render, and a failed
/// advance leaves the event undelivered so a later catch-up re-renders it
/// (a duplicate message is possible; the metric counter on the renderer is
/// the observable hook). Advances are monotonic per consumer.
async fn advance_cursor(
    state: &AgentGatewayState,
    session_id: &str,
    consumer: &str,
    seq: i64,
) -> Result<(), String> {
    let Some(persistence) = state.persistence() else {
        return Ok(());
    };
    persistence
        .delivery_advance(session_id, consumer, seq)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Subscribes to the run's live delivery channel.
fn subscribe_to_run(
    state: &AgentGatewayState,
    run_id: &str,
) -> Option<broadcast::Receiver<GatewayEvent>> {
    state
        .store
        .read()
        .runs
        .get(run_id)
        .and_then(|run| run.sender.as_ref().map(|sender| sender.subscribe()))
}

/// Replays one run's retained events with seq >= after_seq. The durable
/// path pages through `event.replay` and resumes from the retention floor
/// when the requested cursor is too old (pruned events cannot be recovered;
/// the caller filters already-delivered sequences).
async fn replay_run_events(
    state: &AgentGatewayState,
    run_id: &str,
    after_seq: i64,
) -> Vec<(i64, String, Value)> {
    let Some(persistence) = state.persistence() else {
        let store = state.store.read();
        return store
            .runs
            .get(run_id)
            .map(|run| {
                run.events
                    .iter()
                    .filter(|event| (event.seq as i64) >= after_seq)
                    .map(|event| (event.seq as i64, event.event.clone(), event.data.clone()))
                    .collect()
            })
            .unwrap_or_default();
    };
    let mut events = Vec::new();
    let mut after = after_seq;
    loop {
        let payload = json!({
            "run_id": run_id,
            "after_seq": after,
            "max_events": 256,
            "max_bytes": 65536,
        });
        match persistence.event_replay(&payload) {
            Ok(data) => {
                let rows = replay_rows(&data);
                let truncated = data
                    .get("truncated")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let last = rows.last().map(|(seq, _, _)| *seq);
                events.extend(rows);
                if !truncated {
                    break;
                }
                let Some(last) = last else { break };
                after = last;
            }
            Err(error) if error.code == "cursor_too_old" => {
                // The cursor precedes the retention floor: resume from the
                // oldest available sequence (the caller filters delivered
                // ones below).
                after = 1;
            }
            Err(error) => {
                tracing::warn!("telegram event replay failed: {error}");
                break;
            }
        }
    }
    events
}

/// Parses one `event.replay` page into (seq, event_type, data) rows.
fn replay_rows(data: &Value) -> Vec<(i64, String, Value)> {
    data.get("rows")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(|row| {
                    let seq = row.get(0)?.as_i64()?;
                    let event_type = row.get(3)?.as_str()?.to_string();
                    let payload = serde_json::from_str(row.get(4)?.as_str()?).ok()?;
                    Some((seq, event_type, payload))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_message(
        chat_id: i64,
        chat_type: &str,
        message_id: i64,
        thread: Option<i64>,
        text: Option<&str>,
        from: Option<i64>,
    ) -> TgMessage {
        TgMessage {
            message_id,
            date: 1,
            chat: TgChat {
                id: chat_id,
                chat_type: chat_type.to_string(),
                title: None,
            },
            from: from.map(|id| TgUser {
                id,
                is_bot: false,
                first_name: None,
                username: None,
            }),
            text: text.map(ToOwned::to_owned),
            message_thread_id: thread,
            is_topic_message: thread.map(|_| true),
        }
    }

    fn make_update(message: TgMessage) -> (TgUpdate, TgMessage) {
        let update = TgUpdate {
            update_id: 11,
            message: Some(message.clone()),
        };
        (update, message)
    }

    #[test]
    fn parse_command_recognizes_only_canonical_commands() {
        assert_eq!(
            parse_command("/new"),
            (Some("new".to_string()), String::new())
        );
        assert_eq!(
            parse_command("/stop@fixture_bot"),
            (Some("stop".to_string()), String::new())
        );
        assert_eq!(
            parse_command("/COMPACT"),
            (Some("compact".to_string()), String::new())
        );
        assert_eq!(
            parse_command("/status detail"),
            (Some("status".to_string()), "detail".to_string())
        );
        assert_eq!(
            parse_command("/unknown x"),
            (None, "/unknown x".to_string())
        );
        assert_eq!(parse_command("hello"), (None, "hello".to_string()));
    }

    #[test]
    fn envelope_maps_private_group_and_topic_chats_stably() {
        let (update, message) = make_update(make_message(
            555,
            "private",
            101,
            None,
            Some("hello"),
            Some(555),
        ));
        let envelope =
            envelope_from_message(&update, &message, "fixture_bot").expect("dm envelope");
        assert_eq!(envelope.platform, "telegram");
        assert_eq!(envelope.profile, "telegram");
        assert_eq!(envelope.account_id, "fixture_bot");
        assert_eq!(envelope.chat_id, "555");
        assert_eq!(envelope.thread_id, None);
        assert_eq!(envelope.user_id, "555");
        assert_eq!(envelope.message_id, "555:101");
        assert_eq!(envelope.content, "hello");
        assert_eq!(
            session_id_for("fixture_bot", 555, None),
            "telegram:fixture_bot:555:"
        );

        let (update, message) = make_update(make_message(
            -1001234,
            "supergroup",
            102,
            Some(7),
            Some("topic question"),
            Some(555),
        ));
        let envelope =
            envelope_from_message(&update, &message, "fixture_bot").expect("topic envelope");
        assert_eq!(envelope.chat_id, "-1001234");
        assert_eq!(envelope.thread_id.as_deref(), Some("7"));
        assert_eq!(
            session_id_for("fixture_bot", -1001234, Some(7)),
            "telegram:fixture_bot:-1001234:7"
        );

        let (update, message) = make_update(make_message(
            -1001234,
            "supergroup",
            103,
            None,
            Some("general question"),
            Some(555),
        ));
        let envelope =
            envelope_from_message(&update, &message, "fixture_bot").expect("general envelope");
        assert_eq!(envelope.thread_id, None);
        assert_eq!(
            session_id_for("fixture_bot", -1001234, None),
            "telegram:fixture_bot:-1001234:"
        );
        // The general topic and a named topic are different sessions; the
        // same chat+thread is always the same session.
        assert_ne!(
            session_id_for("fixture_bot", -1001234, None),
            session_id_for("fixture_bot", -1001234, Some(7))
        );
    }

    #[test]
    fn envelope_extracts_commands_and_ignores_non_text_or_senderless_messages() {
        let (update, message) = make_update(make_message(
            555,
            "private",
            104,
            None,
            Some("/new"),
            Some(555),
        ));
        let envelope =
            envelope_from_message(&update, &message, "fixture_bot").expect("command envelope");
        assert_eq!(envelope.command.as_deref(), Some("new"));
        assert_eq!(envelope.content, "");

        let (update, message) = make_update(make_message(
            555,
            "private",
            105,
            None,
            Some("   "),
            Some(555),
        ));
        assert!(
            envelope_from_message(&update, &message, "fixture_bot").is_none(),
            "blank text is not user input"
        );

        let (update, message) =
            make_update(make_message(555, "private", 106, None, Some("hello"), None));
        assert!(
            envelope_from_message(&update, &message, "fixture_bot").is_none(),
            "senderless messages are not user input"
        );
    }

    #[test]
    fn dedup_windows_are_bounded_and_detect_duplicates() {
        let mut dedup = DedupWindows::new(3);
        assert!(!dedup.seen_update(1));
        assert!(dedup.seen_update(1), "same update_id is a duplicate");
        assert!(!dedup.seen_update(2));
        assert!(!dedup.seen_update(3));
        assert!(
            !dedup.seen_update(4),
            "the oldest entry fell out of the window"
        );
        assert!(dedup.seen_update(4));

        assert!(!dedup.seen_message("555:101"));
        assert!(dedup.seen_message("555:101"), "same message is a duplicate");
        assert!(
            !dedup.seen_message("555:102"),
            "different messages are distinct"
        );
    }

    #[test]
    fn session_consumer_and_control_ids_are_deterministic() {
        assert_eq!(session_id_for("b", 1, None), "telegram:b:1:");
        assert_eq!(session_id_for("b", 1, Some(2)), "telegram:b:1:2");
        assert_eq!(control_session_id("b"), "telegram-control:b");
        assert_eq!(run_consumer("r1"), "telegram:run:r1");
        assert_eq!(OFFSET_CONSUMER, "telegram:offset");
    }

    #[test]
    fn default_config_builds_an_https_capable_client() {
        let config = TelegramConfig::default();
        assert_eq!(config.api_base, "https://api.telegram.org");
        // Constructing the client with the default production base must
        // succeed (no I/O happens here): the https scheme is served by the
        // TLS connector, never rejected by an http-only connector.
        let api = TelegramApi::new(&config);
        let _ = api;
    }

    #[tokio::test]
    async fn https_uri_is_accepted_by_the_connector() {
        // A refused local connection proves the https scheme is accepted by
        // the connector and reaches the network layer (an http-only
        // connector would reject the scheme before any connection attempt).
        let mut connector = TelegramConnector::new();
        let uri: Uri = "https://127.0.0.1:1/bot1/getMe".parse().expect("uri");
        let error = match connector.call(uri).await {
            Ok(_) => panic!("the connection must be refused"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            io::ErrorKind::ConnectionRefused,
            "the https URI must reach the TCP layer: {error}"
        );
    }

    #[test]
    fn session_active_run_prefers_the_gate_then_the_most_recent_store_run() {
        use crate::gateway::store::{GatewayEvent, GatewayStore, RunRecord};
        use std::sync::atomic::AtomicBool;

        fn run(store: &mut GatewayStore, id: &str, status: &str, last_timestamp: u64) {
            let event = GatewayEvent {
                event_id: format!("{id}-e1"),
                seq: 1,
                event: "run.started".to_string(),
                run_id: id.to_string(),
                timestamp: last_timestamp,
                data: serde_json::json!({}),
            };
            store.runs.insert(
                id.to_string(),
                RunRecord {
                    run_id: id.to_string(),
                    session_id: "telegram:b:1:".to_string(),
                    parent_run_id: None,
                    status: status.to_string(),
                    events: vec![event],
                    sender: None,
                    cancel_requested: Arc::new(AtomicBool::new(false)),
                },
            );
        }

        let active_runs = Arc::new(Mutex::new(HashMap::new()));
        let mut store = GatewayStore::default();
        run(&mut store, "old-zombie", "started", 100);
        run(&mut store, "stale-stopping", "stopping", 200);
        run(&mut store, "done", "completed", 300);

        // With a gated run, the gate wins even when the store also holds
        // active-looking runs.
        active_runs
            .lock()
            .expect("active runs lock")
            .insert("telegram:b:1:".to_string(), "gated".to_string());
        assert_eq!(
            session_active_run(&active_runs, &store, "telegram:b:1:"),
            Some("gated".to_string())
        );

        // Without a gate, the most recently active started/stopping run is
        // the deterministic target; terminal runs never qualify.
        active_runs
            .lock()
            .expect("active runs lock")
            .remove("telegram:b:1:");
        assert_eq!(
            session_active_run(&active_runs, &store, "telegram:b:1:"),
            Some("stale-stopping".to_string())
        );
        store.runs.remove("stale-stopping");
        store.runs.remove("old-zombie");
        assert_eq!(
            session_active_run(&active_runs, &store, "telegram:b:1:"),
            None,
            "terminal runs must never be targeted"
        );
    }
}
