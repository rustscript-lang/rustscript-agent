//! A4 durable approval bridge.
//!
//! Native composition of the A2 approvals storage with a native hard upper
//! bound that RSS approval policy cannot widen.
//!
//! Ownership (gateway-api plan §1 and §4.5):
//! - RSS owns approval *policy* (`rss/harness/approval.rss`): deciding
//!   auto/manual/never/all for a tool call.
//! - Native Rust owns the durable *bridge* and the *hard deny*: it persists a
//!   pending approval through the production A2 storage program
//!   (`rss/storage/main.rss`, generic `sqlite::*`), resumes exactly once after
//!   an approval, and produces a typed terminal on deny/expire. A native deny
//!   is authoritative and cannot be relaxed by any RSS mode.
//!
//! There is no direct SQL and no private host function here: every durable
//! write is delegated to the RSS storage program through `AgentRunner`, which
//! is the same composition the gateway store uses.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Value as JsonValue, json};
use uuid::Uuid;

use super::rss_runner::{AgentConfig, AgentRunner};

/// Canonical risk classes matching the A2 approvals schema and the harness
/// registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskClass {
    Read,
    Write,
    Execute,
    Privileged,
}

impl RiskClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Execute => "execute",
            Self::Privileged => "privileged",
        }
    }
}

/// Native approval modes (gateway-api plan A4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalMode {
    /// Auto-approve trusted/read, require pending for higher risk.
    Auto,
    /// Always require a pending approval.
    Manual,
    /// Never auto-approve; deny everything.
    Never,
    /// Approve everything (subject to native hard-deny).
    All,
}

impl ApprovalMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
            Self::Never => "never",
            Self::All => "all",
        }
    }
}

/// A request to persist a durable pending approval for one tool call.
#[derive(Clone, Debug)]
pub struct PendingApproval {
    pub run_id: String,
    pub session_id: String,
    pub tool_call_id: String,
    pub tool_name: String,
    pub arguments_json: String,
    pub risk: RiskClass,
    pub requested_at_ms: i64,
    pub expires_at_ms: i64,
}

/// A native deny set that RSS policy cannot widen: tool names and risk
/// classes that are denied regardless of the approval mode.
#[derive(Clone, Debug, Default)]
pub struct NativeDenyPolicy {
    deny_tools: BTreeSet<String>,
    deny_risk: BTreeSet<RiskClass>,
}

impl NativeDenyPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn deny_tool(mut self, tool: impl Into<String>) -> Self {
        self.deny_tools.insert(tool.into());
        self
    }

    pub fn deny_risk(mut self, risk: RiskClass) -> Self {
        self.deny_risk.insert(risk);
        self
    }

    pub fn denies_tool(&self, tool: &str) -> bool {
        self.deny_tools.contains(tool)
    }

    pub fn denies_risk(&self, risk: RiskClass) -> bool {
        self.deny_risk.contains(&risk)
    }
}

/// The typed, machine-readable result of an approval decision. `Denied` is
/// always terminal for the run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// Proceed without a durable approval record (auto/all).
    Approve,
    /// Require a durable pending approval before dispatch.
    Pending,
    /// Denied. If native, this is terminal and cannot be relaxed by RSS.
    Denied { native: bool, reason: String },
}

/// A typed approval error carrying the A2 storage code.
#[derive(Clone, Debug)]
pub struct ApprovalError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ApprovalError {}

/// Result of resolving a pending approval. `Resumed` carries the approval id
/// for exactly-once dispatch; `Terminal` carries a typed terminal reason and
/// the typed outcome code (`denied` | `expired`) the resume uses to select
/// the tool-result code (`approval_denied` | `approval_expired`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// The approval transitioned to `approved` exactly once: the run resumes.
    Resumed { approval_id: String },
    /// The approval was already resolved (no row transitioned): no second
    /// resume. This preserves exactly-once dispatch.
    AlreadyResolved,
    /// The approval was denied or expired: the run terminates with a typed
    /// terminal reason and outcome code.
    Terminal {
        approval_id: String,
        reason: String,
        code: String,
    },
}

/// The bridge composes the A2 storage program. The storage command envelope
/// matches `rss/storage/main.rss` (the same shape `StorageRunner` uses).
pub struct ApprovalBridge {
    storage: AgentRunner,
    db_path: String,
    deny: NativeDenyPolicy,
}

impl ApprovalBridge {
    /// Builds a bridge over the production A2 storage program, persisting to
    /// `db_path` with the given SQLite root (the directory that contains the
    /// database file, so the generic sqlite root check permits the file).
    pub fn open(
        sqlite_root: &Path,
        db_path: &Path,
        config: AgentConfig,
        deny: NativeDenyPolicy,
    ) -> Result<Self, String> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("rss")
            .join("storage")
            .join("main.rss");
        let mut config = config;
        config = config.with_sqlite_root(sqlite_root);
        let storage = AgentRunner::from_file(root, config)
            .map_err(|e| format!("compile RSS storage program: {e}"))?;
        Ok(Self {
            storage,
            db_path: db_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            deny,
        })
    }

    /// Builds a bridge over an already-compiled storage runner (used by the
    /// gateway so the program is compiled once).
    pub fn new(storage: AgentRunner, db_path: String, deny: NativeDenyPolicy) -> Self {
        Self {
            storage,
            db_path,
            deny,
        }
    }

    /// The native hard upper bound. RSS approval policy (approval.rss) is fed
    /// `native_hard_deny` from here and can only narrow it.
    pub fn native_deny_policy(&self) -> &NativeDenyPolicy {
        &self.deny
    }

    /// Decides an approval from the native deny policy and the RSS policy's
    /// per-mode action. `rss_action` is the string action the approval policy
    /// produced; the native deny overrides it for any denied tool/risk.
    pub fn decide(&self, tool_name: &str, risk: RiskClass, rss_action: &str) -> ApprovalDecision {
        let native_denied = self.deny.denies_tool(tool_name) || self.deny.denies_risk(risk);
        if native_denied {
            return ApprovalDecision::Denied {
                native: true,
                reason: format!("native policy denies {} ({})", tool_name, risk.as_str()),
            };
        }
        match rss_action {
            "approve" => ApprovalDecision::Approve,
            "pending" => ApprovalDecision::Pending,
            _ => ApprovalDecision::Denied {
                native: false,
                reason: format!("approval policy denied {} ({})", tool_name, risk.as_str()),
            },
        }
    }

    /// Persists a durable pending approval through the A2 storage program.
    ///
    /// `approval_id` is generated by the CALLER and known BEFORE the durable
    /// request starts (the P2 deadline-orphan contract): the storage layer
    /// `INSERT OR IGNOREs` by id, so a late retry of the same request is
    /// idempotent — it can never duplicate the row, and the caller can
    /// always compensate THAT SPECIFIC row afterwards. Returns the persisted
    /// approval id, or a typed error.
    pub fn request_pending(
        &self,
        request: &PendingApproval,
        approval_id: &str,
    ) -> Result<String, ApprovalError> {
        let payload = json!({
            "id": approval_id,
            "run_id": request.run_id,
            "session_id": request.session_id,
            "tool_call_id": request.tool_call_id,
            "tool_name": request.tool_name,
            "arguments_json": request.arguments_json,
            "risk_class": request.risk.as_str(),
            "decision_scope": "",
            "one_time": 1,
            "requested_at_ms": request.requested_at_ms,
            "expires_at_ms": request.expires_at_ms,
        });
        let result = self.command("approval.request", &payload)?;
        // The A2 storage returns the persisted row as a query result under
        // `data.rows`; an empty result means the guard rejected the insert
        // (unknown run, or run not in a resolvable status).
        let row_count = self.data_row_count(&result);
        if row_count == 0 {
            return Err(ApprovalError {
                code: "approval_persist_failed".to_string(),
                message: "approval.request did not persist a pending row".to_string(),
            });
        }
        Ok(approval_id.to_string())
    }

    /// Resolves a pending approval with exactly-once semantics.
    ///
    /// - `approve=true` transitions pending -> approved. Only the first caller
    ///   sees `Resumed`; later callers see `AlreadyResolved` (the A2 storage
    ///   guards `WHERE state='pending'`, so `rows_affected` is 0 the second
    ///   time). Exactly-once dispatch is therefore guaranteed.
    /// - `approve=false` transitions pending -> denied -> `Terminal`.
    ///
    /// The default decision reason text is recorded; callers that carry a
    /// caller-supplied reason use [`Self::resolve_with_reason`].
    pub fn resolve(
        &self,
        approval_id: &str,
        approve: bool,
        resolver: &str,
        now_ms: i64,
    ) -> Result<Resolution, ApprovalError> {
        self.resolve_with_reason(approval_id, approve, resolver, "", now_ms)
    }

    /// Like [`Self::resolve`], but records the caller-supplied `reason` as
    /// the durable `decision_reason` (an empty reason keeps the default
    /// text, so the existing callers' payloads are byte-identical).
    pub fn resolve_with_reason(
        &self,
        approval_id: &str,
        approve: bool,
        resolver: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<Resolution, ApprovalError> {
        let state = if approve { "approved" } else { "denied" };
        let default_reason = if approve {
            "approved by resolver"
        } else {
            "denied by resolver"
        };
        let decision_reason = if reason.is_empty() {
            default_reason
        } else {
            reason
        };
        let payload = json!({
            "id": approval_id,
            "state": state,
            "resolver": resolver,
            "decision_reason": decision_reason,
            "resolved_at_ms": now_ms,
        });
        let result = self.command("approval.resolve", &payload)?;
        if self.row_count(&result) == 1 {
            Ok(if approve {
                Resolution::Resumed {
                    approval_id: approval_id.to_string(),
                }
            } else {
                Resolution::Terminal {
                    approval_id: approval_id.to_string(),
                    reason: "approval denied".to_string(),
                    code: "denied".to_string(),
                }
            })
        } else {
            // No row transitioned: already resolved (approved, denied, or
            // expired) or the run is no longer resolvable. A deny that
            // cannot transition is an expiry-class terminal (the row is
            // already terminal), never a fresh deny.
            if approve {
                Ok(Resolution::AlreadyResolved)
            } else {
                Ok(Resolution::Terminal {
                    approval_id: approval_id.to_string(),
                    reason: "approval already resolved or expired".to_string(),
                    code: "expired".to_string(),
                })
            }
        }
    }

    /// Expires every pending approval at or before `now_ms` (A2 storage
    /// sweep). Returns how many rows were expired.
    pub fn expire(&self, now_ms: i64) -> Result<i64, ApprovalError> {
        let payload = json!({ "now_ms": now_ms });
        let result = self.command("approval.expire", &payload)?;
        Ok(self.row_count(&result))
    }

    /// Cancels ONE specific approval id (the typed `approval.cancel` op):
    /// the P2 deadline-orphan compensation durably expires exactly the row
    /// whose blocking `approval.request` outlived the run deadline. The
    /// storage update is pending-only, so a resolved row is never
    /// downgraded and a different id (a legitimate park) is never touched;
    /// a missing row is a typed no-op. Returns how many rows transitioned.
    pub fn cancel(
        &self,
        approval_id: &str,
        resolver: &str,
        now_ms: i64,
    ) -> Result<i64, ApprovalError> {
        let payload = json!({
            "id": approval_id,
            "resolver": resolver,
            "resolved_at_ms": now_ms,
        });
        let result = self.command("approval.cancel", &payload)?;
        Ok(self.row_count(&result))
    }

    fn command(&self, op: &str, payload: &JsonValue) -> Result<JsonValue, ApprovalError> {
        use rustscript_vm::Value as VmValue;
        let input = VmValue::map(vec![
            (VmValue::string("op"), VmValue::string(op)),
            (
                VmValue::string("request_id"),
                VmValue::string(Uuid::new_v4().to_string()),
            ),
            (
                VmValue::string("db_path"),
                VmValue::string(self.db_path.clone()),
            ),
            (
                VmValue::string("db_mode"),
                VmValue::string("read_write_create"),
            ),
            (VmValue::string("busy_timeout_ms"), VmValue::Int(5_000)),
            (VmValue::string("max_rows"), VmValue::Int(128)),
            (VmValue::string("max_bytes"), VmValue::Int(65_536)),
            (VmValue::string("max_events"), VmValue::Int(128)),
            (VmValue::string("max_messages"), VmValue::Int(128)),
            (VmValue::string("now_ms"), VmValue::Int(0)),
            (
                VmValue::string("payload_json"),
                VmValue::string(payload.to_string()),
            ),
        ]);
        let result = self
            .storage
            .run_with_context(input)
            .map_err(|e| ApprovalError {
                code: "storage_unavailable".to_string(),
                message: format!("run RSS storage op {op}: {e}"),
            })?;
        let json_result = vm_to_json(&result);
        if json_result.get("ok") != Some(&JsonValue::Bool(true)) {
            return Err(ApprovalError {
                code: json_result
                    .get("code")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("storage_error")
                    .to_string(),
                message: json_result
                    .get("message")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("storage command failed")
                    .to_string(),
            });
        }
        Ok(json_result)
    }

    fn row_count(&self, result: &JsonValue) -> i64 {
        result
            .get("rows_affected")
            .and_then(JsonValue::as_i64)
            .unwrap_or(0)
    }

    /// Returns the number of rows returned by a query result stored under
    /// `data.rows` (used by `approval.request`, whose persisted row comes back
    /// as a query result).
    fn data_row_count(&self, result: &JsonValue) -> i64 {
        result
            .get("data")
            .and_then(|data| data.get("rows"))
            .and_then(JsonValue::as_array)
            .map(|rows| rows.len() as i64)
            .unwrap_or(0)
    }
}

/// Converts one VM value into JSON (mirror of the gateway renderer).
fn vm_to_json(value: &rustscript_vm::Value) -> JsonValue {
    use rustscript_vm::Value as VmValue;
    match value {
        VmValue::Null => JsonValue::Null,
        VmValue::Int(v) => json!(v),
        VmValue::Float(v) => serde_json::Number::from_f64(*v)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        VmValue::Bool(v) => json!(v),
        VmValue::String(v) => JsonValue::String(v.to_string()),
        VmValue::Bytes(v) => JsonValue::String(String::from_utf8_lossy(v).into_owned()),
        VmValue::Array(v) => JsonValue::Array(v.iter().map(vm_to_json).collect()),
        VmValue::Map(e) => JsonValue::Object(
            e.iter()
                .map(|(k, v)| (vm_key_to_string(k), vm_to_json(v)))
                .collect(),
        ),
        VmValue::Callable(_) => JsonValue::String("<callable>".to_string()),
    }
}

fn vm_key_to_string(value: &rustscript_vm::Value) -> String {
    use rustscript_vm::Value as VmValue;
    match value {
        VmValue::String(v) => v.to_string(),
        other => vm_to_json(other).to_string(),
    }
}
