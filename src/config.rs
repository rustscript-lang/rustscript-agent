//! Gateway and agent-runner configuration.
//!
//! Every lifecycle bound (concurrency, timeout, delivery capacity, retention,
//! cancellation grace) is validated here so the service can rely on positive
//! values. Configuration is native-owned; RSS never reads ambient config.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rustscript_vm::{HttpConfig, MAX_OUTPUT_BYTES, MAX_STDIN_BYTES, MAX_TIMEOUT, SqlitePolicy};
use serde_json::{Map, Value, json};

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

/// The maximum serialized provider-option payload retained in a run context.
pub const MAX_PROVIDER_OPTIONS_BYTES: usize = 16 * 1024;

/// The maximum UTF-8 byte length of one idempotency key persisted by admission.
/// Keys must also be non-empty and contain no Unicode whitespace or control
/// characters; the service validates this policy before invoking admission RSS.
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 4 * 1024;

/// Maximum UTF-8 byte length of a persisted provider name.
///
/// Production identifiers (`openai`, `anthropic`, `local-agent`, custom
/// profile names) are far shorter than this. 256 bytes is a conservative
/// cap that still leaves sqlite::query headroom after the 64 KiB admission
/// SELECT budget, the 4 KiB idempotency key, and a duplicated `provider`
/// column next to `input_json`.
pub const MAX_PROVIDER_NAME_BYTES: usize = 256;

/// Maximum UTF-8 byte length of a persisted model name.
///
/// Real model ids (`gpt-4o`, `claude-3-5-sonnet-20241022`, `local-agent`)
/// are well under 128 bytes. 1024 bytes is a conservative production cap
/// that blocks a model-padded `input_json` from also overflowing the
/// duplicated `model` column in the post-commit run SELECT.
pub const MAX_MODEL_NAME_BYTES: usize = 1024;

/// RSS `sqlite::query` result budget used by the post-commit admission
/// SELECTs in `rss/storage/admission.rss`. The host counts every column
/// name plus every raw cell (Null=1, Int/Float=8, Bool=1, text=len) and
/// omits the row when the next row would exceed this cap.
pub const ADMISSION_QUERY_RESULT_LIMIT_BYTES: usize = 64 * 1024;
/// RSS `sqlite::query` result budget used by both the pre-commit idempotency
/// lookup SELECT and the post-commit idempotency SELECT.
pub const ADMISSION_IDEMPOTENCY_QUERY_LIMIT_BYTES: usize = 8 * 1024;

/// Production `request_hash` / `idempotency_hash` prefix.
pub const REQUEST_HASH_PREFIX: &str = "fnv64:";
/// Hex digits after [`REQUEST_HASH_PREFIX`].
pub const REQUEST_HASH_HEX_DIGITS: usize = 16;
/// Exact UTF-8 byte length of a production `fnv64:` request hash.
pub const REQUEST_HASH_BYTES: usize = REQUEST_HASH_PREFIX.len() + REQUEST_HASH_HEX_DIGITS;

/// Hyphenated UUID string produced by `Uuid::new_v4().to_string()`.
pub const ADMISSION_UUID_BYTES: usize = 36;

/// `sha256:` plus 64 lowercase hex digits from the registry identity.
pub const ADMISSION_SCRIPT_HASH_BYTES: usize = 71;

/// sqlite::query integer/float cell size used by the host byte estimator.
const SQLITE_QUERY_INT_BYTES: usize = 8;

/// RSS admission reads the persisted context in run, session, and message
/// result envelopes, each capped at 64 KiB. `input_json` cannot exceed that
/// host budget by itself; the exact estimator is the pre-transaction gate
/// that also counts duplicated provider/model cells, the idempotency key,
/// generated UUID/status/timestamps, and every column name.
pub const MAX_RUN_CONTEXT_STORAGE_BYTES: usize = ADMISSION_QUERY_RESULT_LIMIT_BYTES;

/// sqlite::query cell kind used by the admission estimator and row decoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionSqliteCellKind {
    Text,
    Integer,
}

/// One SELECT column shared by the estimator, row decoder, admission literals,
/// and RSS parity tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionQueryColumn {
    pub name: &'static str,
    pub kind: AdmissionSqliteCellKind,
}

impl AdmissionQueryColumn {
    pub const fn text(name: &'static str) -> Self {
        Self {
            name,
            kind: AdmissionSqliteCellKind::Text,
        }
    }

    pub const fn integer(name: &'static str) -> Self {
        Self {
            name,
            kind: AdmissionSqliteCellKind::Integer,
        }
    }
}

/// Post-commit `runs` SELECT columns from `rss/storage/admission.rss`.
pub const ADMISSION_RUN_QUERY_COLUMNS: &[AdmissionQueryColumn] = &[
    AdmissionQueryColumn::text("id"),
    AdmissionQueryColumn::text("session_id"),
    AdmissionQueryColumn::text("parent_run_id"),
    AdmissionQueryColumn::text("status"),
    AdmissionQueryColumn::text("input_json"),
    AdmissionQueryColumn::text("provider"),
    AdmissionQueryColumn::text("model"),
    AdmissionQueryColumn::text("script_hash"),
    AdmissionQueryColumn::text("idempotency_scope"),
    AdmissionQueryColumn::text("idempotency_key"),
    AdmissionQueryColumn::integer("turn_count"),
    AdmissionQueryColumn::integer("input_tokens"),
    AdmissionQueryColumn::integer("output_tokens"),
    AdmissionQueryColumn::text("error_code"),
    AdmissionQueryColumn::text("error_message"),
    AdmissionQueryColumn::text("recovery_reason"),
    AdmissionQueryColumn::integer("created_at_ms"),
    AdmissionQueryColumn::integer("started_at_ms"),
    AdmissionQueryColumn::integer("finished_at_ms"),
    AdmissionQueryColumn::integer("updated_at_ms"),
];

pub const ADMISSION_RUN_COL_ID: usize = 0;
pub const ADMISSION_RUN_COL_SESSION_ID: usize = 1;
pub const ADMISSION_RUN_COL_PARENT_RUN_ID: usize = 2;
pub const ADMISSION_RUN_COL_STATUS: usize = 3;
pub const ADMISSION_RUN_COL_INPUT_JSON: usize = 4;
pub const ADMISSION_RUN_COL_PROVIDER: usize = 5;
pub const ADMISSION_RUN_COL_MODEL: usize = 6;
pub const ADMISSION_RUN_COL_SCRIPT_HASH: usize = 7;

pub const ADMISSION_RUN_QUERY_COLUMN_NAME_BYTES: usize =
    slice_column_name_bytes(ADMISSION_RUN_QUERY_COLUMNS);

pub const ADMISSION_SESSION_QUERY_COLUMNS: &[AdmissionQueryColumn] = &[
    AdmissionQueryColumn::text("id"),
    AdmissionQueryColumn::text("profile"),
    AdmissionQueryColumn::text("platform"),
    AdmissionQueryColumn::text("account_id"),
    AdmissionQueryColumn::text("chat_id"),
    AdmissionQueryColumn::text("thread_id"),
    AdmissionQueryColumn::text("user_id"),
    AdmissionQueryColumn::integer("generation"),
    AdmissionQueryColumn::text("status"),
    AdmissionQueryColumn::text("system_prompt"),
    AdmissionQueryColumn::text("model"),
    AdmissionQueryColumn::text("provider"),
    AdmissionQueryColumn::text("toolset_hash"),
    AdmissionQueryColumn::text("metadata_json"),
    AdmissionQueryColumn::integer("last_message_seq"),
    AdmissionQueryColumn::integer("created_at_ms"),
    AdmissionQueryColumn::integer("updated_at_ms"),
];

pub const ADMISSION_MESSAGE_QUERY_COLUMNS: &[AdmissionQueryColumn] = &[
    AdmissionQueryColumn::text("id"),
    AdmissionQueryColumn::text("session_id"),
    AdmissionQueryColumn::integer("ordinal"),
    AdmissionQueryColumn::text("role"),
    AdmissionQueryColumn::text("content_json"),
    AdmissionQueryColumn::text("name"),
    AdmissionQueryColumn::text("tool_call_id"),
    AdmissionQueryColumn::text("parent_message_id"),
    AdmissionQueryColumn::integer("token_estimate"),
    AdmissionQueryColumn::integer("compacted"),
    AdmissionQueryColumn::text("metadata_json"),
    AdmissionQueryColumn::text("run_id"),
    AdmissionQueryColumn::text("finish_reason"),
    AdmissionQueryColumn::integer("created_at_ms"),
];

/// Pre-commit idempotency lookup SELECT (8192-byte budget).
pub const ADMISSION_IDEMPOTENCY_LOOKUP_COLUMNS: &[AdmissionQueryColumn] = &[
    AdmissionQueryColumn::text("scope"),
    AdmissionQueryColumn::text("key"),
    AdmissionQueryColumn::text("request_hash"),
    AdmissionQueryColumn::text("resource_type"),
    AdmissionQueryColumn::text("resource_id"),
    AdmissionQueryColumn::text("state"),
    AdmissionQueryColumn::text("response_json"),
];

/// Post-commit idempotency SELECT columns.
pub const ADMISSION_IDEMPOTENCY_QUERY_COLUMNS: &[AdmissionQueryColumn] = &[
    AdmissionQueryColumn::text("scope"),
    AdmissionQueryColumn::text("key"),
    AdmissionQueryColumn::text("request_hash"),
    AdmissionQueryColumn::text("resource_type"),
    AdmissionQueryColumn::text("resource_id"),
    AdmissionQueryColumn::text("state"),
    AdmissionQueryColumn::text("response_json"),
    AdmissionQueryColumn::integer("created_at_ms"),
    AdmissionQueryColumn::integer("expires_at_ms"),
    AdmissionQueryColumn::integer("completed_at_ms"),
];

pub const ADMISSION_RUN_STATUS: &str = "running";
pub const ADMISSION_SESSION_STATUS: &str = "active";
pub const ADMISSION_SESSION_PROFILE: &str = "gateway";
pub const ADMISSION_MESSAGE_ROLE: &str = "user";
pub const ADMISSION_METADATA_JSON: &str = "{}";
pub const ADMISSION_IDEMPOTENCY_SCOPE: &str = "api:chat";
pub const ADMISSION_RESOURCE_TYPE: &str = "run";
pub const ADMISSION_IDEMPOTENCY_STATE: &str = "completed";
const ADMISSION_IDEMPOTENCY_RESPONSE_PREFIX_BYTES: usize = 11; // {"run_id":"
const ADMISSION_IDEMPOTENCY_RESPONSE_SUFFIX_BYTES: usize = 21; // ","status":"running"}

const fn slice_column_name_bytes(columns: &[AdmissionQueryColumn]) -> usize {
    let mut total = 0;
    let mut index = 0;
    while index < columns.len() {
        total += columns[index].name.len();
        index += 1;
    }
    total
}

/// Column names in SELECT order for RSS parity tests and diagnostics.
pub fn admission_query_column_names(columns: &[AdmissionQueryColumn]) -> Vec<&'static str> {
    columns.iter().map(|column| column.name).collect()
}

/// Index of `name` in a typed admission SELECT descriptor list.
pub fn admission_query_column_index(columns: &[AdmissionQueryColumn], name: &str) -> Option<usize> {
    columns.iter().position(|column| column.name == name)
}

/// UTF-8 byte lengths of every variable cell in the post-commit admission
/// SELECTs. Generated UUID/status/timestamp/integer cells use the sqlite
/// host's raw-cell sizes; text cells use the stored UTF-8 length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionSqliteCellLens {
    pub run_id: usize,
    pub session_id: usize,
    pub parent_run_id: usize,
    pub input_json: usize,
    pub provider: usize,
    pub model: usize,
    pub script_hash: usize,
    pub idempotency_scope: usize,
    pub idempotency_key: usize,
    pub platform: usize,
    pub profile: usize,
    pub system_prompt: usize,
    pub message_id: usize,
    pub request_hash: usize,
    pub has_idempotency: bool,
}

impl AdmissionSqliteCellLens {
    pub fn for_tests() -> Self {
        Self {
            run_id: ADMISSION_UUID_BYTES,
            session_id: ADMISSION_UUID_BYTES,
            parent_run_id: 0,
            input_json: 0,
            provider: 0,
            model: 0,
            script_hash: ADMISSION_SCRIPT_HASH_BYTES,
            idempotency_scope: ADMISSION_IDEMPOTENCY_SCOPE.len(),
            idempotency_key: 0,
            platform: 0,
            profile: ADMISSION_SESSION_PROFILE.len(),
            system_prompt: 0,
            message_id: ADMISSION_UUID_BYTES,
            request_hash: 0,
            has_idempotency: false,
        }
    }
}

/// sqlite::query byte totals for the post-commit admission SELECTs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionQueryEstimate {
    pub run_bytes: usize,
    pub session_bytes: usize,
    pub message_bytes: usize,
    pub idempotency_bytes: usize,
    pub idempotency_lookup_bytes: usize,
}

impl AdmissionQueryEstimate {
    /// Fail closed when any SELECT would exceed its sqlite::query budget.
    pub fn ensure_fits(self) -> Result<(), AdmissionQueryBudgetError> {
        ensure_query_budget("run", self.run_bytes, ADMISSION_QUERY_RESULT_LIMIT_BYTES)?;
        ensure_query_budget(
            "session",
            self.session_bytes,
            ADMISSION_QUERY_RESULT_LIMIT_BYTES,
        )?;
        ensure_query_budget(
            "message",
            self.message_bytes,
            ADMISSION_QUERY_RESULT_LIMIT_BYTES,
        )?;
        if self.idempotency_bytes > 0 {
            ensure_query_budget(
                "idempotency",
                self.idempotency_bytes,
                ADMISSION_IDEMPOTENCY_QUERY_LIMIT_BYTES,
            )?;
        }
        if self.idempotency_lookup_bytes > 0 {
            ensure_query_budget(
                "idempotency_lookup",
                self.idempotency_lookup_bytes,
                ADMISSION_IDEMPOTENCY_QUERY_LIMIT_BYTES,
            )?;
        }
        Ok(())
    }
}

/// Fail-closed arithmetic or budget errors from the admission estimator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionQueryBudgetError {
    Overflow,
    ExceedsLimit {
        query: &'static str,
        bytes: usize,
        limit: usize,
    },
}

impl std::fmt::Display for AdmissionQueryBudgetError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overflow => formatter.write_str("admission query byte estimate overflowed"),
            Self::ExceedsLimit {
                query,
                bytes,
                limit,
            } => write!(
                formatter,
                "admission {query} SELECT estimate {bytes} exceeds the {limit}-byte sqlite::query budget"
            ),
        }
    }
}

impl std::error::Error for AdmissionQueryBudgetError {}

/// Estimates every post-commit admission SELECT against the sqlite host's
/// column-name + raw-cell accounting. Checked addition fail-closes on
/// overflow instead of wrapping.
pub fn estimate_admission_query_bytes(
    lens: AdmissionSqliteCellLens,
) -> Result<AdmissionQueryEstimate, AdmissionQueryBudgetError> {
    let idempotency_bytes = if lens.has_idempotency {
        estimate_select_bytes(
            ADMISSION_IDEMPOTENCY_QUERY_COLUMNS,
            &idempotency_select_cells(lens),
        )?
    } else {
        0
    };
    let idempotency_lookup_bytes = if lens.has_idempotency {
        estimate_select_bytes(
            ADMISSION_IDEMPOTENCY_LOOKUP_COLUMNS,
            &idempotency_lookup_select_cells(lens),
        )?
    } else {
        0
    };
    Ok(AdmissionQueryEstimate {
        run_bytes: estimate_select_bytes(ADMISSION_RUN_QUERY_COLUMNS, &run_select_cells(lens))?,
        session_bytes: estimate_select_bytes(
            ADMISSION_SESSION_QUERY_COLUMNS,
            &session_select_cells(lens),
        )?,
        message_bytes: estimate_select_bytes(
            ADMISSION_MESSAGE_QUERY_COLUMNS,
            &message_select_cells(lens),
        )?,
        idempotency_bytes,
        idempotency_lookup_bytes,
    })
}

/// Visible-name grammar shared by provider, model, and idempotency keys:
/// one or more UTF-8 scalar values, no whitespace or controls, counted in
/// bytes.
pub fn validate_visible_name(value: &str, field: &str, max_bytes: usize) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value.len() > max_bytes {
        return Err(format!("{field} exceeds the {max_bytes}-byte limit"));
    }
    if value
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(format!(
            "{field} must contain only visible non-whitespace, non-control UTF-8 characters"
        ));
    }
    Ok(())
}

/// Production `request_hash` / `idempotency_hash` grammar: `fnv64:` plus
/// exactly 16 lowercase hex digits.
pub fn validate_request_hash(value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix(REQUEST_HASH_PREFIX) else {
        return Err("request_hash must use the fnv64:<16 lowercase hex> format".to_string());
    };
    if hex.len() != REQUEST_HASH_HEX_DIGITS
        || !hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(
            "request_hash must be fnv64: followed by exactly 16 lowercase hex digits".to_string(),
        );
    }
    debug_assert_eq!(value.len(), REQUEST_HASH_BYTES);
    Ok(())
}

fn ensure_query_budget(
    query: &'static str,
    bytes: usize,
    limit: usize,
) -> Result<(), AdmissionQueryBudgetError> {
    if bytes > limit {
        Err(AdmissionQueryBudgetError::ExceedsLimit {
            query,
            bytes,
            limit,
        })
    } else {
        Ok(())
    }
}

fn sqlite_add(total: usize, extra: usize) -> Result<usize, AdmissionQueryBudgetError> {
    total
        .checked_add(extra)
        .ok_or(AdmissionQueryBudgetError::Overflow)
}

fn sqlite_add_int(total: usize) -> Result<usize, AdmissionQueryBudgetError> {
    sqlite_add(total, SQLITE_QUERY_INT_BYTES)
}

fn estimate_select_bytes(
    columns: &[AdmissionQueryColumn],
    cells: &[usize],
) -> Result<usize, AdmissionQueryBudgetError> {
    if columns.len() != cells.len() {
        return Err(AdmissionQueryBudgetError::Overflow);
    }
    let mut total = 0;
    for column in columns {
        total = sqlite_add(total, column.name.len())?;
    }
    for (column, cell) in columns.iter().zip(cells) {
        total = match column.kind {
            AdmissionSqliteCellKind::Integer => sqlite_add_int(total)?,
            AdmissionSqliteCellKind::Text => sqlite_add(total, *cell)?,
        };
    }
    Ok(total)
}

fn run_select_cells(lens: AdmissionSqliteCellLens) -> Vec<usize> {
    let mut cells = vec![0; ADMISSION_RUN_QUERY_COLUMNS.len()];
    cells[ADMISSION_RUN_COL_ID] = lens.run_id;
    cells[ADMISSION_RUN_COL_SESSION_ID] = lens.session_id;
    cells[ADMISSION_RUN_COL_PARENT_RUN_ID] = lens.parent_run_id;
    cells[ADMISSION_RUN_COL_STATUS] = ADMISSION_RUN_STATUS.len();
    cells[ADMISSION_RUN_COL_INPUT_JSON] = lens.input_json;
    cells[ADMISSION_RUN_COL_PROVIDER] = lens.provider;
    cells[ADMISSION_RUN_COL_MODEL] = lens.model;
    cells[ADMISSION_RUN_COL_SCRIPT_HASH] = lens.script_hash;
    cells[admission_query_column_index(ADMISSION_RUN_QUERY_COLUMNS, "idempotency_scope")
        .expect("idempotency_scope is part of the run SELECT descriptor")] = lens.idempotency_scope;
    cells[admission_query_column_index(ADMISSION_RUN_QUERY_COLUMNS, "idempotency_key")
        .expect("idempotency_key is part of the run SELECT descriptor")] = lens.idempotency_key;
    cells
}

fn session_select_cells(lens: AdmissionSqliteCellLens) -> Vec<usize> {
    let names = ADMISSION_SESSION_QUERY_COLUMNS;
    let mut cells = vec![0; names.len()];
    cells[admission_query_column_index(names, "id").expect("session id")] = lens.session_id;
    cells[admission_query_column_index(names, "profile").expect("session profile")] = lens.profile;
    cells[admission_query_column_index(names, "platform").expect("session platform")] =
        lens.platform;
    cells[admission_query_column_index(names, "account_id").expect("session account_id")] =
        lens.session_id;
    cells[admission_query_column_index(names, "status").expect("session status")] =
        ADMISSION_SESSION_STATUS.len();
    cells[admission_query_column_index(names, "system_prompt").expect("session system_prompt")] =
        lens.system_prompt;
    cells[admission_query_column_index(names, "model").expect("session model")] = lens.model;
    cells[admission_query_column_index(names, "provider").expect("session provider")] =
        lens.provider;
    cells[admission_query_column_index(names, "metadata_json").expect("session metadata_json")] =
        ADMISSION_METADATA_JSON.len();
    cells
}

fn message_select_cells(lens: AdmissionSqliteCellLens) -> Vec<usize> {
    let names = ADMISSION_MESSAGE_QUERY_COLUMNS;
    let mut cells = vec![0; names.len()];
    cells[admission_query_column_index(names, "id").expect("message id")] = lens.message_id;
    cells[admission_query_column_index(names, "session_id").expect("message session_id")] =
        lens.session_id;
    cells[admission_query_column_index(names, "role").expect("message role")] =
        ADMISSION_MESSAGE_ROLE.len();
    cells[admission_query_column_index(names, "content_json").expect("message content_json")] =
        lens.input_json;
    cells[admission_query_column_index(names, "metadata_json").expect("message metadata_json")] =
        ADMISSION_METADATA_JSON.len();
    cells[admission_query_column_index(names, "run_id").expect("message run_id")] = lens.run_id;
    cells
}

fn idempotency_response_bytes(lens: AdmissionSqliteCellLens) -> usize {
    ADMISSION_IDEMPOTENCY_RESPONSE_PREFIX_BYTES
        + lens.run_id
        + ADMISSION_IDEMPOTENCY_RESPONSE_SUFFIX_BYTES
}

fn idempotency_lookup_select_cells(lens: AdmissionSqliteCellLens) -> Vec<usize> {
    vec![
        lens.idempotency_scope,
        lens.idempotency_key,
        lens.request_hash,
        ADMISSION_RESOURCE_TYPE.len(),
        lens.run_id,
        ADMISSION_IDEMPOTENCY_STATE.len(),
        idempotency_response_bytes(lens),
    ]
}

fn idempotency_select_cells(lens: AdmissionSqliteCellLens) -> Vec<usize> {
    let mut cells = idempotency_lookup_select_cells(lens);
    cells.extend_from_slice(&[0, 0, 0]);
    cells
}

const MAX_PROVIDER_OPTION_STRING_BYTES: usize = 4096;
const MAX_PROVIDER_OPTION_KEYS: usize = 32;
/// Object of scalar values only. Nested objects/arrays are OptionsTooDeep.
const MAX_PROVIDER_OPTION_DEPTH: usize = 1;

/// Errors raised while resolving a provider profile for a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderProfileError {
    EmptyName,
    NameTooLong,
    InvalidName,
    OptionsMissing,
    OptionsTooLarge,
    OptionsTooDeep,
    OptionsTooComplex,
    OptionStringTooLong,
    OptionsNotObject,
    UnknownOption(String),
    CredentialBearingOption(String),
    UnsafeUrl(String),
    InvalidOptionValue(String),
}

impl std::fmt::Display for ProviderProfileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyName => formatter.write_str("provider profile name is empty"),
            Self::NameTooLong => formatter.write_str("provider profile name is too long"),
            Self::InvalidName => formatter.write_str(
                "provider profile name must contain only visible non-whitespace, non-control UTF-8 characters",
            ),
            Self::OptionsMissing => formatter.write_str("provider options are missing"),
            Self::OptionsTooLarge => {
                formatter.write_str("provider options exceed the serialized size limit")
            }
            Self::OptionsTooDeep => {
                formatter.write_str("provider options exceed the nesting limit")
            }
            Self::OptionsTooComplex => {
                formatter.write_str("provider options contain too many keys")
            }
            Self::OptionStringTooLong => formatter.write_str("provider option string is too long"),
            Self::OptionsNotObject => formatter.write_str("provider options must be a JSON object"),
            Self::UnknownOption(key) => write!(formatter, "unknown provider option {key:?}"),
            Self::CredentialBearingOption(key) => {
                write!(
                    formatter,
                    "credential-bearing provider option {key:?} is not allowed"
                )
            }
            Self::UnsafeUrl(reason) => write!(formatter, "provider base_url is unsafe: {reason}"),
            Self::InvalidOptionValue(key) => {
                write!(formatter, "provider option {key:?} has an invalid value")
            }
        }
    }
}

impl std::error::Error for ProviderProfileError {}

/// A validated, secret-safe provider profile snapshot.
#[derive(Clone, Debug, PartialEq)]
pub struct ProviderProfile {
    pub name: String,
    options: Value,
}

impl ProviderProfile {
    /// Validates and canonicalizes provider options at the configuration
    /// boundary. Only the explicit safe option reference below can enter a
    /// run context; credentials, headers, and opaque provider extensions are
    /// rejected instead of redacted.
    pub fn new(name: impl Into<String>, options: Value) -> Result<Self, ProviderProfileError> {
        let name = name.into();
        if name.is_empty() {
            return Err(ProviderProfileError::EmptyName);
        }
        if name.len() > MAX_PROVIDER_NAME_BYTES {
            return Err(ProviderProfileError::NameTooLong);
        }
        if name
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(ProviderProfileError::InvalidName);
        }
        let options = canonicalize_provider_options(&options)?;
        if serde_json::to_vec(&options)
            .map(|bytes| bytes.len() > MAX_PROVIDER_OPTIONS_BYTES)
            .unwrap_or(true)
        {
            return Err(ProviderProfileError::OptionsTooLarge);
        }
        Ok(Self { name, options })
    }

    /// Returns a built-in non-empty profile for a provider name.
    pub fn builtin(provider: impl Into<String>) -> Result<Self, ProviderProfileError> {
        let name = provider.into();
        let protocol = match name.to_ascii_lowercase().as_str() {
            "anthropic" => "anthropic-messages",
            "google" | "gemini" => "google-generative-ai",
            "openai" | "openai-compatible" => "openai-chat-completions",
            "local-agent" | "local" => "local-agent",
            _ => "provider",
        };
        Self::new(
            name.clone(),
            json!({
                "profile": name,
                "protocol": protocol,
            }),
        )
    }

    pub fn options(&self) -> &Value {
        &self.options
    }

    pub fn to_json(&self) -> Value {
        json!({"name": self.name, "options": self.options})
    }

    pub fn from_json(value: &Value) -> Result<Self, ProviderProfileError> {
        let name = value
            .get("name")
            .and_then(Value::as_str)
            .ok_or(ProviderProfileError::EmptyName)?;
        let options = value
            .get("options")
            .cloned()
            .ok_or(ProviderProfileError::OptionsMissing)?;
        Self::new(name, options)
    }
}

/// Explicit provider-option reference. These values are request-shaping
/// controls only; authentication and arbitrary transport extensions remain
/// outside the persisted run context.
fn canonicalize_provider_options(value: &Value) -> Result<Value, ProviderProfileError> {
    if json_nesting_depth(value) > MAX_PROVIDER_OPTION_DEPTH {
        return Err(ProviderProfileError::OptionsTooDeep);
    }
    let Some(entries) = value.as_object() else {
        return Err(ProviderProfileError::OptionsNotObject);
    };
    if entries.len() > MAX_PROVIDER_OPTION_KEYS {
        return Err(ProviderProfileError::OptionsTooComplex);
    }
    let mut keys = entries.keys().collect::<Vec<_>>();
    keys.sort_unstable();
    let mut canonical = Map::new();
    for key in keys {
        if key.len() > 128 {
            return Err(ProviderProfileError::OptionStringTooLong);
        }
        if is_credential_bearing_option_key(key) {
            return Err(ProviderProfileError::CredentialBearingOption(key.clone()));
        }
        let value = entries
            .get(key)
            .expect("sorted provider option key came from object");
        canonical.insert(key.clone(), canonicalize_provider_option(key, value)?);
    }
    Ok(Value::Object(canonical))
}

fn canonicalize_provider_option(key: &str, value: &Value) -> Result<Value, ProviderProfileError> {
    match key {
        "profile" | "protocol" | "reasoning_effort" => {
            let text = value
                .as_str()
                .ok_or_else(|| ProviderProfileError::InvalidOptionValue(key.to_string()))?;
            if text.is_empty() {
                return Err(ProviderProfileError::InvalidOptionValue(key.to_string()));
            }
            if text.len() > MAX_PROVIDER_OPTION_STRING_BYTES {
                return Err(ProviderProfileError::OptionStringTooLong);
            }
            Ok(Value::String(text.to_string()))
        }
        "base_url" => {
            let text = value
                .as_str()
                .ok_or_else(|| ProviderProfileError::InvalidOptionValue(key.to_string()))?;
            if text.len() > MAX_PROVIDER_OPTION_STRING_BYTES {
                return Err(ProviderProfileError::OptionStringTooLong);
            }
            let url = url::Url::parse(text)
                .map_err(|error| ProviderProfileError::UnsafeUrl(error.to_string()))?;
            if !matches!(url.scheme(), "http" | "https") {
                return Err(ProviderProfileError::UnsafeUrl(
                    "scheme must be http or https".to_string(),
                ));
            }
            if url.host_str().is_none() {
                return Err(ProviderProfileError::UnsafeUrl(
                    "host is missing".to_string(),
                ));
            }
            if !url.username().is_empty() || url.password().is_some() {
                return Err(ProviderProfileError::UnsafeUrl(
                    "credentials are not allowed".to_string(),
                ));
            }
            if url.query().is_some() {
                return Err(ProviderProfileError::UnsafeUrl(
                    "query strings are not allowed".to_string(),
                ));
            }
            if url.fragment().is_some() {
                return Err(ProviderProfileError::UnsafeUrl(
                    "fragments are not allowed".to_string(),
                ));
            }
            Ok(Value::String(text.to_string()))
        }
        "temperature" | "top_p" => {
            if value.as_f64().is_none() {
                return Err(ProviderProfileError::InvalidOptionValue(key.to_string()));
            }
            Ok(value.clone())
        }
        "max_output_tokens" => {
            if value.as_u64().is_none() {
                return Err(ProviderProfileError::InvalidOptionValue(key.to_string()));
            }
            Ok(value.clone())
        }
        "stream" => {
            if !value.is_boolean() {
                return Err(ProviderProfileError::InvalidOptionValue(key.to_string()));
            }
            Ok(value.clone())
        }
        _ => Err(ProviderProfileError::UnknownOption(key.to_string())),
    }
}

fn json_nesting_depth(value: &Value) -> usize {
    match value {
        Value::Array(values) => values
            .iter()
            .map(json_nesting_depth)
            .max()
            .unwrap_or(0)
            .saturating_add(1),
        Value::Object(entries) => entries
            .values()
            .map(json_nesting_depth)
            .max()
            .unwrap_or(0)
            .saturating_add(1),
        _ => 0,
    }
}

fn is_credential_bearing_option_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "apikey"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "secret"
            | "password"
            | "authorization"
            | "credential"
            | "key"
            | "header"
            | "headers"
            | "cookie"
            | "cookies"
    )
}

/// Errors raised while validating effective run limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunLimitsError {
    Zero(&'static str),
    TooLarge(&'static str, u64),
    EmptyWorkspace,
    RelativeWorkspace,
    InvalidWorkspace(String),
}

impl std::fmt::Display for RunLimitsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Zero(field) => write!(formatter, "{field} must be positive"),
            Self::TooLarge(field, value) => write!(formatter, "{field} is too large: {value}"),
            Self::EmptyWorkspace => formatter.write_str("workspace_root is empty"),
            Self::RelativeWorkspace => formatter.write_str("workspace_root must be absolute"),
            Self::InvalidWorkspace(path) => write!(formatter, "workspace_root is invalid: {path}"),
        }
    }
}

impl std::error::Error for RunLimitsError {}

/// Immutable execution limits captured by each admitted run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunLimits {
    pub max_turns: u64,
    pub max_tool_calls: u64,
    pub max_tool_output_bytes: u64,
    pub workspace_root: PathBuf,
}

impl RunLimits {
    pub const MAX_TURNS: u64 = 1_000_000;
    pub const MAX_TOOL_CALLS: u64 = 1_000_000;
    pub const MAX_TOOL_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

    pub fn new(
        max_turns: u64,
        max_tool_calls: u64,
        max_tool_output_bytes: u64,
        workspace_root: impl AsRef<Path>,
    ) -> Result<Self, RunLimitsError> {
        validate_limit_numbers(max_turns, max_tool_calls, max_tool_output_bytes)?;
        let workspace_root = canonical_workspace_root(workspace_root.as_ref())?;
        Ok(Self {
            max_turns,
            max_tool_calls,
            max_tool_output_bytes,
            workspace_root,
        })
    }

    pub fn validate(&self) -> Result<(), RunLimitsError> {
        self.normalized().map(|_| ())
    }

    pub fn normalized(&self) -> Result<Self, RunLimitsError> {
        let workspace_root = canonical_workspace_root(&self.workspace_root)?;
        validate_limit_numbers(
            self.max_turns,
            self.max_tool_calls,
            self.max_tool_output_bytes,
        )?;
        Ok(Self {
            max_turns: self.max_turns,
            max_tool_calls: self.max_tool_calls,
            max_tool_output_bytes: self.max_tool_output_bytes,
            workspace_root,
        })
    }

    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("max_turns".to_string(), json!(self.max_turns));
        object.insert("max_tool_calls".to_string(), json!(self.max_tool_calls));
        object.insert(
            "max_tool_output_bytes".to_string(),
            json!(self.max_tool_output_bytes),
        );
        object.insert(
            "workspace_root".to_string(),
            Value::String(self.workspace_root.to_string_lossy().into_owned()),
        );
        Value::Object(object)
    }

    pub fn from_json(value: &Value) -> Result<Self, RunLimitsError> {
        Self::new(
            value
                .get("max_turns")
                .and_then(Value::as_u64)
                .ok_or(RunLimitsError::Zero("max_turns"))?,
            value
                .get("max_tool_calls")
                .and_then(Value::as_u64)
                .ok_or(RunLimitsError::Zero("max_tool_calls"))?,
            value
                .get("max_tool_output_bytes")
                .and_then(Value::as_u64)
                .ok_or(RunLimitsError::Zero("max_tool_output_bytes"))?,
            value
                .get("workspace_root")
                .and_then(Value::as_str)
                .ok_or(RunLimitsError::EmptyWorkspace)?,
        )
    }

    /// Fail-closed default: requires a validated absolute current working
    /// directory. Never falls back to `/`.
    pub fn try_default() -> Result<Self, RunLimitsError> {
        let workspace_root = std::env::current_dir()
            .map_err(|error| RunLimitsError::InvalidWorkspace(error.to_string()))?;
        Self::new(64, 128, 1024 * 1024, workspace_root)
    }
}

impl Default for RunLimits {
    fn default() -> Self {
        Self::try_default()
            .expect("RunLimits::default requires a validated absolute current working directory")
    }
}

fn validate_limit_numbers(
    max_turns: u64,
    max_tool_calls: u64,
    max_tool_output_bytes: u64,
) -> Result<(), RunLimitsError> {
    if max_turns == 0 {
        return Err(RunLimitsError::Zero("max_turns"));
    }
    if max_tool_calls == 0 {
        return Err(RunLimitsError::Zero("max_tool_calls"));
    }
    if max_tool_output_bytes == 0 {
        return Err(RunLimitsError::Zero("max_tool_output_bytes"));
    }
    if max_turns > RunLimits::MAX_TURNS {
        return Err(RunLimitsError::TooLarge("max_turns", max_turns));
    }
    if max_tool_calls > RunLimits::MAX_TOOL_CALLS {
        return Err(RunLimitsError::TooLarge("max_tool_calls", max_tool_calls));
    }
    if max_tool_output_bytes > RunLimits::MAX_TOOL_OUTPUT_BYTES {
        return Err(RunLimitsError::TooLarge(
            "max_tool_output_bytes",
            max_tool_output_bytes,
        ));
    }
    Ok(())
}

fn canonical_workspace_root(path: &Path) -> Result<PathBuf, RunLimitsError> {
    if path.as_os_str().is_empty() {
        return Err(RunLimitsError::EmptyWorkspace);
    }
    if path.to_string_lossy().contains('\0') {
        return Err(RunLimitsError::InvalidWorkspace(
            "path contains NUL".to_string(),
        ));
    }
    if !path.is_absolute() {
        return Err(RunLimitsError::RelativeWorkspace);
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| RunLimitsError::InvalidWorkspace(error.to_string()))?;
    if !canonical.is_dir() {
        return Err(RunLimitsError::InvalidWorkspace(
            "path is not a directory".to_string(),
        ));
    }
    Ok(canonical)
}

/// Hard upper bounds for native terminal/process tool budgets.
pub const MAX_PROCESS_TOOL_OUTPUT_BYTES: usize = MAX_OUTPUT_BYTES;
pub const MAX_PROCESS_TOOL_STREAM_BYTES: usize = MAX_OUTPUT_BYTES;
pub const MAX_PROCESS_TOOL_STDIN_BYTES: usize = MAX_STDIN_BYTES;
pub const MAX_PROCESS_TOOL_PROCESSES: usize = 1_024;
pub const MAX_PROCESS_TOOL_PROCESSES_PER_OWNER: usize = 256;
pub const MAX_PROCESS_TOOL_TIMEOUT: Duration = MAX_TIMEOUT;
pub const MAX_PROCESS_TOOL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Validated native configuration for bounded terminal and process tools.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessToolConfig {
    /// Canonical absolute workspace used as the default child cwd.
    pub workspace_root: PathBuf,
    /// Default spawn timeout when a request omits `timeout_ms`.
    pub default_timeout: Duration,
    /// Maximum spawn/lifecycle timeout accepted from configuration or a request.
    pub max_timeout: Duration,
    /// Maximum model-visible content bytes in one tool result.
    pub max_output_bytes: usize,
    /// Maximum retained stdout/stderr ring bytes passed to the core process API.
    pub max_stream_bytes: usize,
    /// Maximum initial stdin bytes accepted by `terminal`.
    pub max_stdin_bytes: usize,
    /// Maximum retained process records in one table.
    pub max_processes: usize,
    /// Maximum retained process records for one profile/session/run owner.
    pub max_processes_per_owner: usize,
    /// Upper bound for owner cleanup and table drop.
    pub cleanup_timeout: Duration,
}

impl ProcessToolConfig {
    /// Returns fail-closed defaults rooted at `workspace`.
    pub fn for_workspace(root: impl Into<PathBuf>) -> Self {
        Self {
            workspace_root: root.into(),
            default_timeout: Duration::from_secs(30),
            max_timeout: MAX_PROCESS_TOOL_TIMEOUT,
            max_output_bytes: 64 * 1024,
            max_stream_bytes: 1024 * 1024,
            max_stdin_bytes: 1024 * 1024,
            max_processes: 32,
            max_processes_per_owner: 8,
            cleanup_timeout: Duration::from_secs(2),
        }
    }

    /// Validates every process-tool budget. Invalid values fail closed.
    pub fn validate(&self) -> Result<(), String> {
        validate_process_workspace(&self.workspace_root)?;
        if self.default_timeout.is_zero() || self.default_timeout > self.max_timeout {
            return Err("default_timeout must be positive and at most max_timeout".to_string());
        }
        if self.max_timeout.is_zero() || self.max_timeout > MAX_PROCESS_TOOL_TIMEOUT {
            return Err("max_timeout must be positive and at most 3600 seconds".to_string());
        }
        validate_positive_bounded(
            self.max_output_bytes,
            MAX_PROCESS_TOOL_OUTPUT_BYTES,
            "max_output_bytes",
        )?;
        validate_positive_bounded(
            self.max_stream_bytes,
            MAX_PROCESS_TOOL_STREAM_BYTES,
            "max_stream_bytes",
        )?;
        validate_positive_bounded(
            self.max_stdin_bytes,
            MAX_PROCESS_TOOL_STDIN_BYTES,
            "max_stdin_bytes",
        )?;
        validate_positive_bounded(
            self.max_processes,
            MAX_PROCESS_TOOL_PROCESSES,
            "max_processes",
        )?;
        validate_positive_bounded(
            self.max_processes_per_owner,
            MAX_PROCESS_TOOL_PROCESSES_PER_OWNER,
            "max_processes_per_owner",
        )?;
        if self.max_processes_per_owner > self.max_processes {
            return Err("max_processes_per_owner must be at most max_processes".to_string());
        }
        if self.cleanup_timeout.is_zero() || self.cleanup_timeout > MAX_PROCESS_TOOL_CLEANUP_TIMEOUT
        {
            return Err("cleanup_timeout must be positive and at most 30 seconds".to_string());
        }
        Ok(())
    }

    /// Returns a copy with a canonical workspace after validation.
    pub fn validated(&self) -> Result<Self, String> {
        self.validate()?;
        Ok(Self {
            workspace_root: std::fs::canonicalize(&self.workspace_root)
                .map_err(|error| format!("workspace_root is invalid: {error}"))?,
            ..self.clone()
        })
    }
}

fn validate_process_workspace(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("workspace_root is empty".to_string());
    }
    if path.to_string_lossy().contains('\0') {
        return Err("workspace_root is invalid: path contains NUL".to_string());
    }
    if !path.is_absolute() {
        return Err("workspace_root must be absolute".to_string());
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| format!("workspace_root is invalid: {error}"))?;
    if !canonical.is_dir() {
        return Err("workspace_root is invalid: path is not a directory".to_string());
    }
    Ok(())
}

fn validate_positive_bounded(value: usize, max: usize, name: &str) -> Result<(), String> {
    if value == 0 {
        return Err(format!("{name} must be positive"));
    }
    if value > max {
        return Err(format!("{name} is too large: {value}"));
    }
    Ok(())
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
        validate_visible_name(&self.model, "model", MAX_MODEL_NAME_BYTES)?;
        if let Some(provider) = self.provider.as_deref().filter(|value| !value.is_empty()) {
            validate_visible_name(provider, "provider", MAX_PROVIDER_NAME_BYTES)?;
        }
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
    fn process_tool_config_fail_closes_on_zero_and_oversize_budgets() {
        let root = std::env::current_dir().expect("current dir");
        let base = ProcessToolConfig::for_workspace(&root);
        base.validate()
            .expect("default process tool config must validate");

        let mut invalid = base.clone();
        invalid.max_timeout = Duration::ZERO;
        assert!(invalid.validate().is_err());

        let mut invalid = base.clone();
        invalid.max_output_bytes = 0;
        assert!(invalid.validate().is_err());

        let mut invalid = base.clone();
        invalid.max_processes = 0;
        assert!(invalid.validate().is_err());

        let mut invalid = base;
        invalid.max_timeout = MAX_PROCESS_TOOL_TIMEOUT + Duration::from_secs(1);
        assert!(invalid.validate().is_err());
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

    #[test]
    fn provider_and_model_bounds_are_conservative_production_caps() {
        assert_eq!(MAX_PROVIDER_NAME_BYTES, 256);
        assert_eq!(MAX_MODEL_NAME_BYTES, 1024);
        const {
            assert!(MAX_PROVIDER_NAME_BYTES < MAX_MODEL_NAME_BYTES);
            assert!(
                MAX_MODEL_NAME_BYTES + MAX_PROVIDER_NAME_BYTES + MAX_IDEMPOTENCY_KEY_BYTES
                    < ADMISSION_QUERY_RESULT_LIMIT_BYTES
            );
        }
    }

    #[test]
    fn visible_name_grammar_rejects_empty_whitespace_and_controls() {
        for value in ["", "has space", "has\nnewline", "has\u{7f}control"] {
            assert!(
                validate_visible_name(value, "model", MAX_MODEL_NAME_BYTES).is_err(),
                "{value:?} must be rejected"
            );
        }
        validate_visible_name("local-agent", "model", MAX_MODEL_NAME_BYTES)
            .expect("a visible production model name must be accepted");
    }

    #[test]
    fn visible_name_counts_utf8_bytes_not_characters() {
        let exact = utf8_visible_token(MAX_MODEL_NAME_BYTES);
        assert!(exact.chars().count() < exact.len());
        validate_visible_name(&exact, "model", MAX_MODEL_NAME_BYTES)
            .expect("a multibyte name at the byte limit must be accepted");
        assert!(
            validate_visible_name(&format!("{exact}a"), "model", MAX_MODEL_NAME_BYTES).is_err()
        );
    }

    #[test]
    fn provider_profile_uses_the_centralized_provider_name_bound() {
        let exact = "p".repeat(MAX_PROVIDER_NAME_BYTES);
        ProviderProfile::new(
            exact.clone(),
            json!({"profile": "p", "protocol": "local-agent"}),
        )
        .expect("a provider name at the centralized bound must be accepted");
        let error = ProviderProfile::new(
            format!("{exact}x"),
            json!({"profile": "p", "protocol": "local-agent"}),
        )
        .expect_err("one byte beyond the provider name bound must be rejected");
        assert_eq!(error, ProviderProfileError::NameTooLong);
    }

    #[test]
    fn run_select_column_names_match_admission_sql() {
        assert_eq!(
            admission_query_column_names(ADMISSION_RUN_QUERY_COLUMNS),
            vec![
                "id",
                "session_id",
                "parent_run_id",
                "status",
                "input_json",
                "provider",
                "model",
                "script_hash",
                "idempotency_scope",
                "idempotency_key",
                "turn_count",
                "input_tokens",
                "output_tokens",
                "error_code",
                "error_message",
                "recovery_reason",
                "created_at_ms",
                "started_at_ms",
                "finished_at_ms",
                "updated_at_ms",
            ]
        );
        assert_eq!(
            ADMISSION_RUN_QUERY_COLUMN_NAME_BYTES,
            ADMISSION_RUN_QUERY_COLUMNS
                .iter()
                .map(|column| column.name.len())
                .sum::<usize>()
        );
        assert_eq!(
            ADMISSION_RUN_QUERY_COLUMNS[ADMISSION_RUN_COL_INPUT_JSON].name,
            "input_json"
        );
        assert_eq!(
            ADMISSION_RUN_QUERY_COLUMNS[ADMISSION_RUN_COL_ID].kind,
            AdmissionSqliteCellKind::Text
        );
        assert_eq!(
            ADMISSION_RUN_QUERY_COLUMNS
                [admission_query_column_index(ADMISSION_RUN_QUERY_COLUMNS, "turn_count").unwrap()]
            .kind,
            AdmissionSqliteCellKind::Integer
        );
    }

    #[test]
    fn admission_query_estimator_accepts_exact_budget_and_rejects_one_byte_over() {
        let mut lens = AdmissionSqliteCellLens::for_tests();
        let baseline = estimate_admission_query_bytes(lens)
            .expect("the baseline fixture must be estimable")
            .run_bytes;
        let padding = ADMISSION_QUERY_RESULT_LIMIT_BYTES
            .checked_sub(baseline)
            .expect("the baseline fixture must sit below the query budget");
        lens.input_json = lens
            .input_json
            .checked_add(padding)
            .expect("padding must fit in usize");
        let estimate =
            estimate_admission_query_bytes(lens).expect("exact budget must be estimable");
        assert_eq!(estimate.run_bytes, ADMISSION_QUERY_RESULT_LIMIT_BYTES);
        estimate
            .ensure_fits()
            .expect("a run SELECT at exactly 65536 bytes must be accepted");

        lens.input_json = lens
            .input_json
            .checked_add(1)
            .expect("one extra byte must fit in usize");
        let over = estimate_admission_query_bytes(lens).expect("one-over must still be estimable");
        assert_eq!(over.run_bytes, ADMISSION_QUERY_RESULT_LIMIT_BYTES + 1);
        let error = over
            .ensure_fits()
            .expect_err("one byte over the query budget must fail closed");
        assert!(matches!(
            error,
            AdmissionQueryBudgetError::ExceedsLimit {
                query: "run",
                bytes: 65537,
                limit: 65536
            }
        ));
    }

    #[test]
    fn admission_query_estimator_counts_duplicated_model_column() {
        let mut lens = AdmissionSqliteCellLens::for_tests();
        lens.model = MAX_MODEL_NAME_BYTES;
        lens.provider = MAX_PROVIDER_NAME_BYTES;
        lens.idempotency_key = MAX_IDEMPOTENCY_KEY_BYTES;
        lens.has_idempotency = true;
        let without_context = estimate_admission_query_bytes(lens)
            .expect("max name cells must be estimable")
            .run_bytes;
        lens.input_json = 48 * 1024;
        let padded =
            estimate_admission_query_bytes(lens).expect("model-padded envelope must estimate");
        assert_eq!(
            padded.run_bytes,
            without_context
                .checked_add(48 * 1024)
                .expect("model-padded envelope must not overflow")
        );
        assert!(
            padded.run_bytes > lens.input_json + lens.idempotency_key,
            "the estimator must count the duplicated model/provider columns on top of input_json and the key"
        );
    }

    #[test]
    fn admission_query_estimator_fail_closes_on_checked_overflow() {
        let mut lens = AdmissionSqliteCellLens::for_tests();
        lens.input_json = usize::MAX;
        assert_eq!(
            estimate_admission_query_bytes(lens),
            Err(AdmissionQueryBudgetError::Overflow)
        );
    }

    #[test]
    fn session_and_message_selects_stay_at_or_below_the_run_select() {
        let mut lens = AdmissionSqliteCellLens::for_tests();
        lens.input_json = 40 * 1024;
        lens.system_prompt = 32 * 1024;
        lens.model = MAX_MODEL_NAME_BYTES;
        lens.provider = MAX_PROVIDER_NAME_BYTES;
        lens.idempotency_key = MAX_IDEMPOTENCY_KEY_BYTES;
        lens.has_idempotency = true;
        let estimate =
            estimate_admission_query_bytes(lens).expect("combined payload must estimate");
        assert!(estimate.message_bytes <= estimate.run_bytes);
        assert!(estimate.session_bytes <= estimate.run_bytes);
        estimate
            .ensure_fits()
            .expect("the combined max-name payload must fit every 64 KiB SELECT");
    }

    #[test]
    fn admission_select_columns_match_rss_script_order() {
        let source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rss/storage/admission.rss"),
        )
        .expect("admission.rss must be readable for column-order parity");
        assert_eq!(
            parse_select_columns(&source, "FROM runs"),
            admission_query_column_names(ADMISSION_RUN_QUERY_COLUMNS)
        );
        assert_eq!(
            parse_select_columns(&source, "FROM sessions"),
            admission_query_column_names(ADMISSION_SESSION_QUERY_COLUMNS)
        );
        assert_eq!(
            parse_select_columns(&source, "FROM messages"),
            admission_query_column_names(ADMISSION_MESSAGE_QUERY_COLUMNS)
        );
        let lookup = parse_first_select_columns(&source, "FROM idempotency_records");
        assert_eq!(
            lookup,
            admission_query_column_names(ADMISSION_IDEMPOTENCY_LOOKUP_COLUMNS)
        );
        assert!(
            source.contains("max_result_bytes: 8192"),
            "pre-commit idempotency SELECT must keep the 8192-byte budget"
        );
        assert_eq!(ADMISSION_IDEMPOTENCY_QUERY_LIMIT_BYTES, 8192);
    }

    #[test]
    fn precommit_idempotency_select_fits_8192_with_max_key_and_hash() {
        let mut lens = AdmissionSqliteCellLens::for_tests();
        lens.idempotency_key = MAX_IDEMPOTENCY_KEY_BYTES;
        lens.request_hash = REQUEST_HASH_BYTES;
        lens.has_idempotency = true;
        let estimate =
            estimate_admission_query_bytes(lens).expect("max key+hash lookup must estimate");
        assert!(estimate.idempotency_lookup_bytes > 0);
        assert!(estimate.idempotency_lookup_bytes <= ADMISSION_IDEMPOTENCY_QUERY_LIMIT_BYTES);
        assert!(estimate.idempotency_bytes <= ADMISSION_IDEMPOTENCY_QUERY_LIMIT_BYTES);
        estimate
            .ensure_fits()
            .expect("max production hash+key must fit the 8192-byte idempotency budgets");
    }

    #[test]
    fn request_hash_grammar_matches_production_fnv64() {
        validate_request_hash("fnv64:0123456789abcdef").expect("canonical hash must be accepted");
        assert_eq!(REQUEST_HASH_BYTES, 22);
        for invalid in [
            "fnv64:0123456789ABCDE",
            "fnv64:0123456789ABCDEF",
            "fnv64:0123456789abcde",
            "fnv64:0123456789abcdef0",
            "sha256:0123456789abcdef",
            "service-test-request-hash",
            "",
        ] {
            assert!(
                validate_request_hash(invalid).is_err(),
                "{invalid:?} must be rejected"
            );
        }
    }

    #[test]
    fn nested_provider_options_are_options_too_deep() {
        let error = ProviderProfile::new("local-agent", json!({"nested": {"too": {"deep": true}}}))
            .expect_err("nested objects must be OptionsTooDeep");
        assert_eq!(error, ProviderProfileError::OptionsTooDeep);
    }

    #[test]
    fn run_limits_try_default_never_falls_back_to_filesystem_root() {
        let limits = RunLimits::try_default().expect("cwd should be a valid workspace in tests");
        assert!(limits.workspace_root.is_absolute());
        let cwd = std::env::current_dir().expect("cwd");
        if cwd != std::path::Path::new("/") {
            assert_ne!(limits.workspace_root, std::path::Path::new("/"));
            assert_ne!(
                RunLimits::default().workspace_root,
                std::path::Path::new("/")
            );
        }
    }

    fn parse_select_columns(source: &str, from_clause: &str) -> Vec<String> {
        parse_all_select_columns(source, from_clause)
            .into_iter()
            .max_by_key(|columns| columns.len())
            .expect("SELECT list")
    }

    fn parse_first_select_columns(source: &str, from_clause: &str) -> Vec<String> {
        parse_all_select_columns(source, from_clause)
            .into_iter()
            .next()
            .expect("first SELECT list")
    }

    fn parse_all_select_columns(source: &str, from_clause: &str) -> Vec<Vec<String>> {
        let mut lists = Vec::new();
        let mut rest = source;
        while let Some(from_at) = rest.find(from_clause) {
            let prefix = &rest[..from_at];
            if let Some(select_at) = prefix.rfind("SELECT") {
                let list = prefix[select_at + "SELECT".len()..]
                    .split(',')
                    .map(|part| part.trim().to_string())
                    .filter(|part| !part.is_empty())
                    .collect::<Vec<_>>();
                if !list.is_empty() {
                    lists.push(list);
                }
            }
            rest = &rest[from_at + from_clause.len()..];
        }
        lists
    }

    fn utf8_visible_token(byte_limit: usize) -> String {
        let mut token = String::new();
        while token.len() + '界'.len_utf8() <= byte_limit {
            token.push('界');
        }
        while token.len() < byte_limit {
            token.push('a');
        }
        assert_eq!(token.len(), byte_limit);
        token
    }
}
