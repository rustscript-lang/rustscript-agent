//! Gateway and agent-runner configuration.
//!
//! Every lifecycle bound (concurrency, timeout, delivery capacity, retention,
//! cancellation grace) is validated here so the service can rely on positive
//! values. Configuration is native-owned; RSS never reads ambient config.

use std::time::Duration;

use rustscript_vm::{HttpConfig, SqlitePolicy};

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
    pub http: HttpConfig,
    pub sqlite: SqlitePolicy,
    pub fuel: Option<u64>,
}

impl AgentGatewayConfig {
    /// Validates that every lifecycle bound is positive.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_concurrent_runs == 0 {
            return Err("max_concurrent_runs must be positive".to_string());
        }
        if self.run_timeout.is_zero() {
            return Err("run_timeout must be positive".to_string());
        }
        if self.event_channel_capacity == 0 {
            return Err("event_channel_capacity must be positive".to_string());
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
        Ok(())
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
            max_events_per_run: 240,
            max_event_bytes: 32 * 1024,
            terminal_run_ttl: Duration::from_secs(60),
            cancellation_grace: Duration::from_secs(5),
            janitor_interval: Duration::from_secs(5),
            terminal_commit_retry_window: Duration::from_secs(300),
            http: HttpConfig::default(),
            sqlite,
            fuel: Some(10_000_000),
        }
    }
}
