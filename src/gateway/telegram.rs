//! Native Telegram Bot API transport: typed client, long-poll updates, and
//! bounded retry policy.
//!
//! The client speaks the Bot API over the existing dependency graph (hyper +
//! hyper-util, already pulled by axum — no new transitive crates). The bot
//! token is embedded in the request URL by Telegram's protocol, so the URL is
//! never logged and the token never appears in `Debug` output; only the
//! method name and the typed outcome are observable.
//!
//! Retry policy (bounded): HTTP 429 sleeps `retry_after` (capped at
//! `max_429_backoff`) for at most `max_429_retries`; HTTP 5xx retries at most
//! `max_5xx_retries` times with capped exponential backoff; any other 4xx is
//! a typed `Api` failure with no retry; transport failures are typed and
//! surfaced immediately (the poller treats them as recoverable). No retry
//! path is unbounded.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::Request as HyperRequest;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tokio::time::timeout;

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
/// timeout failure.
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

/// The minimal HTTP client surface the Bot API needs; the token lives only
/// inside the per-request URL and in this struct (redacted `Debug`).
pub struct TelegramApi {
    api_base: String,
    token: String,
    client: Client<HttpConnector, Full<Bytes>>,
    request_timeout: Duration,
    max_429_retries: usize,
    max_429_backoff: Duration,
    max_5xx_retries: usize,
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
            .finish()
    }
}

impl TelegramApi {
    /// Builds the client from validated configuration. The request timeout
    /// always exceeds the long-poll timeout so a poll round is never cut
    /// short by the client itself.
    pub fn new(config: &TelegramConfig) -> Self {
        let connector = HttpConnector::new();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Self {
            api_base: config.api_base.trim_end_matches('/').to_string(),
            token: config.bot_token.clone(),
            client,
            request_timeout: config.poll_timeout + Duration::from_secs(15),
            max_429_retries: config.max_429_retries,
            max_429_backoff: config.max_429_backoff,
            max_5xx_retries: config.max_5xx_retries,
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
                TelegramError::Transport(format!("Bot API request failed: {error}"))
            })?;
        let status = response.status();
        let bytes = timeout(
            self.request_timeout,
            http_body_util::BodyExt::collect(response.into_body()),
        )
        .await
        .map_err(|_| TelegramError::Transport("Bot API response timed out".to_string()))?
        .map_err(|error| TelegramError::Transport(format!("read Bot API response: {error}")))?
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
