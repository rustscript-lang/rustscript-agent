//! Gateway and agent-runner configuration.
//!
//! Every lifecycle bound (concurrency, timeout, delivery capacity, retention,
//! cancellation grace) is validated here so the service can rely on positive
//! values. Configuration is native-owned; RSS never reads ambient config.

use std::time::Duration;

use rustscript_vm::{HttpConfig, SqlitePolicy};

/// Telegram Bot API adapter configuration.
///
/// Deny-by-default allowlists: every list starts empty and an empty list
/// denies everything. The bot token is redacted in every Debug/log surface.
#[derive(Clone)]
pub struct TelegramConfig {
    /// Bot API token; never logged, redacted in Debug.
    pub bot_token: String,
    /// Bot API base URL (defaults to `https://api.telegram.org`); tests point
    /// this at a local fixture server. Production requires `https`: a plain
    /// `http` base is only accepted for localhost and only with
    /// [`Self::allow_insecure_localhost`] (or under `cfg(test)`), so the
    /// token is never transmitted in cleartext.
    pub api_base: String,
    /// Explicit escape hatch for `http://localhost` fixture bases (tests
    /// and local development only). `https` remains the only production
    /// scheme.
    pub allow_insecure_localhost: bool,
    /// `getUpdates` long-poll timeout in seconds.
    pub poll_timeout: Duration,
    /// Backoff between poll rounds after a transport/API error.
    pub poll_interval: Duration,
    /// Bounded 429 retries (each sleeps `retry_after`, capped at
    /// `max_429_backoff`).
    pub max_429_retries: usize,
    /// Cap for one 429 `retry_after` sleep.
    pub max_429_backoff: Duration,
    /// Bounded 5xx retries (exponential backoff, capped).
    pub max_5xx_retries: usize,
    /// Minimum interval between `editMessageText` calls (delta throttle);
    /// zero edits on every delta.
    pub max_edit_interval: Duration,
    /// Bounded cap on one Bot API response body; a body that exceeds it is
    /// a typed [`TelegramError::ResponseTooLarge`] and is never buffered.
    pub max_response_body_bytes: usize,
    /// Bounded wait for an active run's terminal transition during `/new`
    /// (typed cancel first, then the session reset). When the wait expires
    /// the reset fails with a typed reply and deletes nothing.
    pub new_wait_timeout: Duration,
    /// First-boot offset strategy: when no poll offset was ever persisted,
    /// pending updates (queued while the bot was offline) are drained
    /// without processing by default, so old updates are never replayed
    /// into sessions. Set to false to process pending updates.
    pub drop_pending_updates: bool,
    /// Bounded 401 circuit breaker: after this many consecutive
    /// unauthorized getUpdates failures the poller stops (the adapter is
    /// disabled for the process) instead of retrying forever.
    pub unauthorized_failure_bound: usize,
    /// Bounded capacity of the update_id/message_id dedup windows.
    pub dedup_capacity: usize,
    /// Allowed bot account usernames (case-insensitive); empty denies all.
    pub allowed_accounts: Vec<String>,
    /// Allowed chat ids (negative ids are groups/supergroups); empty denies
    /// all chats.
    pub allowed_chats: Vec<i64>,
    /// Allowed sender user ids; empty denies all users.
    pub allowed_users: Vec<i64>,
}

impl std::fmt::Debug for TelegramConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TelegramConfig")
            .field("bot_token", &"REDACTED")
            .field("api_base", &self.api_base)
            .field("allow_insecure_localhost", &self.allow_insecure_localhost)
            .field("poll_timeout", &self.poll_timeout)
            .field("poll_interval", &self.poll_interval)
            .field("max_429_retries", &self.max_429_retries)
            .field("max_429_backoff", &self.max_429_backoff)
            .field("max_5xx_retries", &self.max_5xx_retries)
            .field("max_edit_interval", &self.max_edit_interval)
            .field("max_response_body_bytes", &self.max_response_body_bytes)
            .field("new_wait_timeout", &self.new_wait_timeout)
            .field("drop_pending_updates", &self.drop_pending_updates)
            .field(
                "unauthorized_failure_bound",
                &self.unauthorized_failure_bound,
            )
            .field("dedup_capacity", &self.dedup_capacity)
            .field("allowed_accounts", &self.allowed_accounts)
            .field("allowed_chats", &self.allowed_chats)
            .field("allowed_users", &self.allowed_users)
            .finish()
    }
}

impl TelegramConfig {
    /// Validates every lifecycle bound; allowlists may stay empty (that is
    /// the deny-by-default posture). The api_base scheme is enforced:
    /// production must be `https`; `http` is only accepted for a localhost
    /// host with the explicit [`Self::allow_insecure_localhost`] escape (or
    /// under `cfg(test)`), so the token is never sent over cleartext.
    pub fn validate(&self) -> Result<(), String> {
        if self.bot_token.trim().is_empty() {
            return Err("telegram bot_token must not be blank".to_string());
        }
        if self.api_base.trim().is_empty() {
            return Err("telegram api_base must not be blank".to_string());
        }
        let base = url::Url::parse(&self.api_base)
            .map_err(|error| format!("telegram api_base is not a valid URL: {error}"))?;
        if !base.username().is_empty() || base.password().is_some() {
            return Err("telegram api_base must not embed credentials".to_string());
        }
        // The token is embedded in the request URL by the Bot API protocol,
        // so the base must be a bare origin: a query string, fragment, or
        // path would smuggle state (and potentially the token) into the URL
        // in ways the client never intends.
        if !base.query().unwrap_or("").is_empty() {
            return Err(
                "telegram api_base must not carry a query string (the token must never enter a query)"
                    .to_string(),
            );
        }
        if base.fragment().is_some() {
            return Err("telegram api_base must not carry a fragment".to_string());
        }
        if !matches!(base.path(), "" | "/") {
            return Err("telegram api_base path must be empty or '/'".to_string());
        }
        match base.scheme() {
            "https" => {}
            "http" => {
                let host = base.host_str().unwrap_or_default();
                let localhost = matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1");
                if !localhost {
                    return Err(
                        "telegram api_base http is only allowed for localhost (the bot token must never travel in cleartext)"
                            .to_string(),
                    );
                }
                if !(self.allow_insecure_localhost || cfg!(test)) {
                    return Err(
                        "telegram api_base http requires allow_insecure_localhost (test fixtures and local development only)"
                            .to_string(),
                    );
                }
            }
            other => {
                return Err(format!(
                    "telegram api_base scheme must be https (got {other})"
                ));
            }
        }
        if self.poll_timeout.is_zero() {
            return Err("telegram poll_timeout must be positive".to_string());
        }
        if self.poll_interval.is_zero() {
            return Err("telegram poll_interval must be positive".to_string());
        }
        if self.max_429_backoff.is_zero() {
            return Err("telegram max_429_backoff must be positive".to_string());
        }
        if self.dedup_capacity == 0 {
            return Err("telegram dedup_capacity must be positive".to_string());
        }
        if self.max_response_body_bytes == 0 {
            return Err("telegram max_response_body_bytes must be positive".to_string());
        }
        if self.new_wait_timeout.is_zero() {
            return Err("telegram new_wait_timeout must be positive".to_string());
        }
        if self.unauthorized_failure_bound == 0 {
            return Err("telegram unauthorized_failure_bound must be positive".to_string());
        }
        Ok(())
    }
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            bot_token: String::new(),
            api_base: "https://api.telegram.org".to_string(),
            allow_insecure_localhost: false,
            poll_timeout: Duration::from_secs(30),
            poll_interval: Duration::from_secs(1),
            max_429_retries: 3,
            max_429_backoff: Duration::from_secs(30),
            max_5xx_retries: 3,
            max_edit_interval: Duration::from_millis(300),
            max_response_body_bytes: 1024 * 1024,
            new_wait_timeout: Duration::from_secs(10),
            drop_pending_updates: true,
            unauthorized_failure_bound: 3,
            dedup_capacity: 512,
            allowed_accounts: Vec::new(),
            allowed_chats: Vec::new(),
            allowed_users: Vec::new(),
        }
    }
}

/// Validated configuration shared by the gateway, AgentService, and runner.
#[derive(Clone, Debug)]
pub struct AgentGatewayConfig {
    pub model: String,
    pub provider: Option<String>,
    pub agent_name: String,
    pub bearer_token: Option<String>,
    pub max_body_bytes: usize,
    pub max_concurrent_runs: usize,
    pub run_timeout: Duration,
    pub event_channel_capacity: usize,
    pub broadcast_capacity: usize,
    pub max_events_per_run: usize,
    pub max_event_bytes: usize,
    pub terminal_run_ttl: Duration,
    pub cancellation_grace: Duration,
    pub janitor_interval: Duration,
    /// Bounded window during which a terminal commit that failed while
    /// storage was down is retried (janitor cadence). After the window the
    /// run's permit/handle/stream are released and the durable side is left
    /// for restart recovery.
    pub terminal_commit_retry_window: Duration,
    /// Bounded terminal-commit retries after a failed persist: the worker
    /// retries this many additional times (with `terminal_persist_retry_delay`
    /// backoff) before registering the terminal as pending for the bounded
    /// retry loop.
    pub terminal_persist_retries: usize,
    /// Backoff between bounded terminal-commit retries.
    pub terminal_persist_retry_delay: Duration,
    /// Bounded in-memory rate limiting applied by the gateway middleware
    /// before any handler runs (per peer IP and per verified bearer
    /// account). Disabled by default; see [`RateLimitConfig`].
    pub rate_limit: RateLimitConfig,
    /// What happens to an active run when its last live SSE subscriber
    /// disconnects (see [`ClientDisconnectPolicy`]). Defaults to
    /// keep-running.
    pub client_disconnect_policy: ClientDisconnectPolicy,
    /// SSE keep-alive interval. Also the upper bound on how quickly a
    /// client disconnect is detected: the next keep-alive write fails, the
    /// SSE body is dropped, and the subscriber drop guard fires.
    pub sse_keepalive_interval: Duration,

    pub http: HttpConfig,
    pub sqlite: SqlitePolicy,
    pub fuel: Option<u64>,
    /// Optional Telegram adapter configuration. When present, the gateway
    /// binary starts the Telegram poller alongside the API server on the
    /// same AgentService/store.
    pub telegram: Option<TelegramConfig>,
}

impl AgentGatewayConfig {
    /// Validates that every lifecycle bound is positive.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_body_bytes == 0 {
            return Err("max_body_bytes must be positive".to_string());
        }
        if self.max_concurrent_runs == 0 {
            return Err("max_concurrent_runs must be positive".to_string());
        }
        if self.run_timeout.is_zero() {
            return Err("run_timeout must be positive".to_string());
        }
        if self.event_channel_capacity == 0 {
            return Err("event_channel_capacity must be positive".to_string());
        }
        if self.broadcast_capacity == 0 {
            return Err("broadcast_capacity must be positive".to_string());
        }
        if self.max_events_per_run == 0 {
            return Err("max_events_per_run must be positive".to_string());
        }
        if self.max_event_bytes == 0 {
            return Err("max_event_bytes must be positive".to_string());
        }
        if self.terminal_run_ttl.is_zero() {
            return Err("terminal_run_ttl must be positive".to_string());
        }
        if self.cancellation_grace.is_zero() {
            return Err("cancellation_grace must be positive".to_string());
        }
        if self.janitor_interval.is_zero() {
            return Err("janitor_interval must be positive".to_string());
        }
        if self.terminal_commit_retry_window.is_zero() {
            return Err("terminal_commit_retry_window must be positive".to_string());
        }
        if self.terminal_persist_retry_delay.is_zero() {
            return Err("terminal_persist_retry_delay must be positive".to_string());
        }
        if self.sse_keepalive_interval.is_zero() {
            return Err("sse_keepalive_interval must be positive".to_string());
        }
        self.rate_limit.validate()?;
        if let Some(telegram) = &self.telegram {
            telegram
                .validate()
                .map_err(|error| format!("invalid Telegram configuration: {error}"))?;
        }
        Ok(())
    }
}

/// Bounded, non-blocking, in-memory token-bucket rate limiting enforced by
/// the gateway middleware before any handler runs.
///
/// Two independent dimensions are tracked: one bucket per peer IP and one
/// bucket per verified bearer account. Every request consumes one token
/// from the peer-IP bucket; authenticated requests additionally consume one
/// token from their account bucket. A request with no token left is
/// rejected with HTTP 429 and a `Retry-After` header (the seconds until at
/// least one token refills). Buckets are keyed by identity and never shared
/// across dimensions, and failed authentication never charges an account
/// bucket: accounts are charged only after the bearer token verifies. The
/// limiter is non-blocking (one short critical section, no I/O) and memory
/// is bounded by `max_buckets`: stale buckets are swept on access and the
/// stalest bucket is evicted at the bound, so the table can never grow
/// without limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Master switch; when disabled the middleware passes every request
    /// through untouched (the other fields still validate).
    pub enabled: bool,
    /// Per-peer-IP burst: tokens available per `window` for one IP.
    pub ip_burst: u32,
    /// Per-account burst: tokens available per `window` for one verified
    /// bearer identity.
    pub account_burst: u32,
    /// Refill window shared by both dimensions: each bucket refills its
    /// burst over one `window`.
    pub window: Duration,
    /// Upper bound on tracked buckets (per-IP and per-account combined);
    /// at the bound the stalest bucket is evicted.
    pub max_buckets: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ip_burst: 60,
            account_burst: 120,
            window: Duration::from_secs(60),
            max_buckets: 10_000,
        }
    }
}

impl RateLimitConfig {
    /// Validates that every bound is positive and within the documented
    /// sane upper bounds (the limiter divides by `window` and stores up to
    /// `max_buckets` entries, so degenerate values are rejected up front).
    fn validate(&self) -> Result<(), String> {
        if self.ip_burst == 0 || self.ip_burst > 1_000_000 {
            return Err("rate_limit.ip_burst must be positive and at most 1000000".to_string());
        }
        if self.account_burst == 0 || self.account_burst > 1_000_000 {
            return Err(
                "rate_limit.account_burst must be positive and at most 1000000".to_string(),
            );
        }
        if self.window.is_zero() || self.window > Duration::from_secs(86_400) {
            return Err("rate_limit.window must be positive and at most 86400 seconds".to_string());
        }
        if self.max_buckets == 0 || self.max_buckets > 1_000_000 {
            return Err("rate_limit.max_buckets must be positive and at most 1000000".to_string());
        }
        Ok(())
    }
}

/// What happens to an active run when its last live SSE subscriber
/// disconnects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientDisconnectPolicy {
    /// Default: the run keeps running after every subscriber disconnects,
    /// and events stay replayable through the `after_seq` cursor once a
    /// client reconnects.
    KeepRunning,
    /// The run is cancelled with the typed `client_disconnect` reason, but
    /// only when the last subscriber disconnects while the run is still
    /// active. Multi-subscriber and reconnect races can never cancel while
    /// at least one subscriber remains, and a normal terminal end never
    /// requests a cancellation.
    CancelOnDisconnect,
}

impl ClientDisconnectPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KeepRunning => "keep-running",
            Self::CancelOnDisconnect => "cancel-on-disconnect",
        }
    }

    /// Parses the environment-variable spelling of the policy.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "keep-running" => Ok(Self::KeepRunning),
            "cancel-on-disconnect" => Ok(Self::CancelOnDisconnect),
            other => Err(format!(
                "unknown client disconnect policy {other:?}; expected keep-running or \
                 cancel-on-disconnect"
            )),
        }
    }
}

impl Default for AgentGatewayConfig {
    fn default() -> Self {
        let mut sqlite = SqlitePolicy::default();
        sqlite.limits.max_statements = 1024;
        Self {
            model: "local-agent".to_string(),
            provider: Some("local-agent".to_string()),
            agent_name: "local-rss-agent".to_string(),
            bearer_token: None,
            max_body_bytes: 4 * 1024 * 1024,
            max_concurrent_runs: 8,
            run_timeout: Duration::from_secs(900),
            event_channel_capacity: 64,
            broadcast_capacity: 64,
            max_events_per_run: 240,
            max_event_bytes: 32 * 1024,
            terminal_run_ttl: Duration::from_secs(60),
            cancellation_grace: Duration::from_secs(5),
            janitor_interval: Duration::from_secs(5),
            terminal_commit_retry_window: Duration::from_secs(300),
            terminal_persist_retries: 3,
            terminal_persist_retry_delay: Duration::from_millis(25),
            rate_limit: RateLimitConfig::default(),
            client_disconnect_policy: ClientDisconnectPolicy::KeepRunning,
            sse_keepalive_interval: Duration::from_secs(10),

            http: HttpConfig::default(),
            sqlite,
            fuel: Some(10_000_000),
            telegram: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        AgentGatewayConfig::default()
            .validate()
            .expect("default configuration must validate");
    }

    #[test]
    fn telegram_option_validates_when_present() {
        let base = AgentGatewayConfig::default();
        let invalid = AgentGatewayConfig {
            telegram: Some(TelegramConfig {
                bot_token: String::new(),
                ..TelegramConfig::default()
            }),
            ..base.clone()
        };
        assert!(
            invalid.validate().is_err(),
            "a configured telegram adapter must validate its own bounds"
        );
        let valid = AgentGatewayConfig {
            telegram: Some(TelegramConfig {
                bot_token: "123:abc".to_string(),
                ..TelegramConfig::default()
            }),
            ..base
        };
        valid.validate().expect("valid telegram config must pass");
    }

    #[test]
    fn max_body_bytes_must_be_positive() {
        let config = AgentGatewayConfig {
            max_body_bytes: 0,
            ..AgentGatewayConfig::default()
        };
        assert!(
            config.validate().is_err(),
            "max_body_bytes must be a validated positive bound"
        );
    }

    #[test]
    fn broadcast_capacity_must_be_positive() {
        let config = AgentGatewayConfig {
            broadcast_capacity: 0,
            ..AgentGatewayConfig::default()
        };
        assert!(
            config.validate().is_err(),
            "broadcast_capacity must be a validated positive bound"
        );
    }

    #[test]
    fn terminal_persist_retry_delay_must_be_positive() {
        let config = AgentGatewayConfig {
            terminal_persist_retry_delay: Duration::ZERO,
            ..AgentGatewayConfig::default()
        };
        assert!(
            config.validate().is_err(),
            "terminal_persist_retry_delay must be a validated positive bound"
        );
    }

    #[test]
    fn sse_keepalive_interval_must_be_positive() {
        let config = AgentGatewayConfig {
            sse_keepalive_interval: Duration::ZERO,
            ..AgentGatewayConfig::default()
        };
        assert!(
            config.validate().is_err(),
            "sse_keepalive_interval must be a validated positive bound"
        );
    }

    #[test]
    fn rate_limit_defaults_validate() {
        RateLimitConfig::default()
            .validate()
            .expect("default rate limit configuration must validate");
    }

    #[test]
    fn rate_limit_bursts_must_be_positive_and_bounded() {
        for burst in [0_u32, 1_000_001] {
            let config = RateLimitConfig {
                ip_burst: burst,
                ..RateLimitConfig::default()
            };
            assert!(
                config.validate().is_err(),
                "ip_burst {burst} must be rejected as out of bounds"
            );
            let config = RateLimitConfig {
                account_burst: burst,
                ..RateLimitConfig::default()
            };
            assert!(
                config.validate().is_err(),
                "account_burst {burst} must be rejected as out of bounds"
            );
        }
    }

    #[test]
    fn rate_limit_window_must_be_positive_and_bounded() {
        for window in [Duration::ZERO, Duration::from_secs(86_401)] {
            let config = RateLimitConfig {
                window,
                ..RateLimitConfig::default()
            };
            assert!(
                config.validate().is_err(),
                "window {window:?} must be rejected as out of bounds"
            );
        }
    }

    #[test]
    fn rate_limit_max_buckets_must_be_positive_and_bounded() {
        for max_buckets in [0_usize, 1_000_001] {
            let config = RateLimitConfig {
                max_buckets,
                ..RateLimitConfig::default()
            };
            assert!(
                config.validate().is_err(),
                "max_buckets {max_buckets} must be rejected as out of bounds"
            );
        }
    }

    #[test]
    fn client_disconnect_policy_defaults_to_keep_running_and_parses() {
        assert_eq!(
            AgentGatewayConfig::default().client_disconnect_policy,
            ClientDisconnectPolicy::KeepRunning
        );
        assert_eq!(
            ClientDisconnectPolicy::parse("keep-running"),
            Ok(ClientDisconnectPolicy::KeepRunning)
        );
        assert_eq!(
            ClientDisconnectPolicy::parse("cancel-on-disconnect"),
            Ok(ClientDisconnectPolicy::CancelOnDisconnect)
        );
        assert!(
            ClientDisconnectPolicy::parse("stop-the-world").is_err(),
            "unknown policy spellings must be rejected"
        );
        assert_eq!(
            ClientDisconnectPolicy::CancelOnDisconnect.as_str(),
            "cancel-on-disconnect"
        );
    }
    #[test]
    fn telegram_api_base_must_be_https_in_production() {
        let base = TelegramConfig {
            bot_token: "123:abc".to_string(),
            ..TelegramConfig::default()
        };
        base.validate()
            .expect("the default https base must validate");
        let http_remote = TelegramConfig {
            api_base: "http://api.telegram.example".to_string(),
            ..base.clone()
        };
        assert!(
            http_remote.validate().is_err(),
            "a non-localhost http api_base must be rejected"
        );
        let ftp = TelegramConfig {
            api_base: "ftp://api.telegram.org".to_string(),
            ..base.clone()
        };
        assert!(
            ftp.validate().is_err(),
            "a non-http(s) scheme must be rejected"
        );
        let credentials = TelegramConfig {
            api_base: "https://user:pass@api.telegram.org".to_string(),
            ..base.clone()
        };
        assert!(
            credentials.validate().is_err(),
            "credentials embedded in api_base must be rejected"
        );
    }

    #[test]
    fn telegram_api_base_http_localhost_uses_the_test_escape() {
        let base = TelegramConfig {
            bot_token: "123:abc".to_string(),
            ..TelegramConfig::default()
        };
        // Unit tests compile with cfg(test): the localhost escape exists.
        let localhost = TelegramConfig {
            api_base: "http://127.0.0.1:9999".to_string(),
            ..base.clone()
        };
        localhost
            .validate()
            .expect("cfg(test) permits localhost http");
        // The explicit flag is the same escape for non-test binaries.
        let explicit = TelegramConfig {
            api_base: "http://localhost:9999".to_string(),
            allow_insecure_localhost: true,
            ..base
        };
        explicit
            .validate()
            .expect("allow_insecure_localhost permits localhost http");
    }

    #[test]
    fn telegram_api_base_rejects_query_fragment_and_path() {
        let base = TelegramConfig {
            bot_token: "123:abc".to_string(),
            ..TelegramConfig::default()
        };
        // The token is embedded in the request URL by the Bot API protocol,
        // so a query string, fragment, or path on the api_base would let
        // configuration smuggle the token (or other state) into the URL in
        // ways the client never intended. Only the bare origin (with an
        // optional trailing slash) is valid.
        for bad in [
            "https://api.telegram.org/?x=1",
            "https://api.telegram.org?x=1",
            "https://api.telegram.org/#frag",
            "https://api.telegram.org#frag",
            "https://api.telegram.org/some/path",
            "https://api.telegram.org/bot123:abc",
        ] {
            let config = TelegramConfig {
                api_base: bad.to_string(),
                ..base.clone()
            };
            assert!(
                config.validate().is_err(),
                "api_base {bad} must be rejected"
            );
        }
        base.validate().expect("the default base must validate");
        let trailing_slash = TelegramConfig {
            api_base: "https://api.telegram.org/".to_string(),
            ..base
        };
        trailing_slash
            .validate()
            .expect("a trailing-slash base is the same origin");
    }

    #[test]
    fn telegram_max_response_body_bytes_must_be_positive() {
        let config = TelegramConfig {
            bot_token: "123:abc".to_string(),
            max_response_body_bytes: 0,
            ..TelegramConfig::default()
        };
        assert!(
            config.validate().is_err(),
            "max_response_body_bytes must be a validated positive bound"
        );
    }

    #[test]
    fn telegram_unauthorized_failure_bound_must_be_positive() {
        let config = TelegramConfig {
            bot_token: "123:abc".to_string(),
            unauthorized_failure_bound: 0,
            ..TelegramConfig::default()
        };
        assert!(
            config.validate().is_err(),
            "unauthorized_failure_bound must be a validated positive bound"
        );
    }

    #[test]
    fn telegram_drop_pending_updates_defaults_to_safe() {
        let config = TelegramConfig::default();
        assert!(
            config.drop_pending_updates,
            "pending updates must be dropped on first boot by default (no replay of old updates)"
        );
    }
}
