//! Injectable durable lifecycle, clock, tokens, and approval.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use parking_lot::Mutex;
use serde_json::{Value, json};
use uuid::Uuid;

use super::types::{
    CapabilityOwner, CapabilityRisk, CommitOutcome, DurableStarted, LifecycleError,
    LifecycleLimits, PrepareMetadata, PrepareOutcome, TokenClaims,
};

/// Wall/monotonic clock used by prepare and commit.
pub trait LifecycleClock: Send + Sync {
    fn now_ms(&self) -> u64;
    fn now(&self) -> Instant;
}

/// Issues opaque, unforgeable execution token identifiers.
pub trait TokenIssuer: Send + Sync {
    fn issue(&self) -> String;
}

/// Durable run/parent/replay/started/result/interrupt boundary.
pub trait DurableToolLifecycle: Send + Sync {
    fn assert_active_run(&self, run_id: &str) -> Result<(), LifecycleError>;
    fn prepare_parent(
        &self,
        run_id: &str,
        call_id: &str,
        tool_name: &str,
    ) -> Result<(), LifecycleError>;
    fn replay_result(
        &self,
        run_id: &str,
        call_id: &str,
        tool_name: &str,
    ) -> Result<Option<Value>, LifecycleError>;
    fn commit_started(&self, record: &DurableStarted) -> Result<(), LifecycleError>;
    fn commit_result(&self, call_id: &str, result: &Value) -> Result<Value, LifecycleError>;
    fn interrupt(&self, call_id: &str) -> Result<(), LifecycleError>;
}

/// Approval policy. Returns the approved risk ceiling.
pub trait ApprovalGate: Send + Sync {
    fn authorize(&self, metadata: &PrepareMetadata) -> Result<CapabilityRisk, LifecycleError>;
}

/// Cooperative cancellation observed at prepare/commit.
pub trait CancellationFlag: Send + Sync {
    fn is_cancelled(&self) -> bool;
}

/// Production clock: unix milliseconds plus monotonic Instant.
#[derive(Debug, Default)]
pub struct SystemClock;

impl LifecycleClock for SystemClock {
    fn now_ms(&self) -> u64 {
        crate::domain::timestamp()
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Unforgeable UUID token issuer.
#[derive(Debug, Default)]
pub struct UuidIssuer;

impl TokenIssuer for UuidIssuer {
    fn issue(&self) -> String {
        Uuid::new_v4().to_string()
    }
}

/// Default gate: approve the requested class as the ceiling.
#[derive(Debug, Default)]
pub struct AllowAllApproval;

impl ApprovalGate for AllowAllApproval {
    fn authorize(&self, metadata: &PrepareMetadata) -> Result<CapabilityRisk, LifecycleError> {
        Ok(metadata.risk_class)
    }
}

/// Default cancellation: never cancelled.
#[derive(Debug, Default)]
pub struct NeverCancelled;

impl CancellationFlag for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// Builder for [`CapabilityLifecycle`].
pub struct CapabilityLifecycleBuilder {
    owner: Option<CapabilityOwner>,
    registry_identity: Option<String>,
    workspace: Option<PathBuf>,
    limits: Option<LifecycleLimits>,
    deadline_ms: Option<u64>,
    clock: Option<Arc<dyn LifecycleClock>>,
    tokens: Option<Arc<dyn TokenIssuer>>,
    durable: Option<Arc<dyn DurableToolLifecycle>>,
    approval: Option<Arc<dyn ApprovalGate>>,
    cancellation: Option<Arc<dyn CancellationFlag>>,
    generation: u64,
}

impl Default for CapabilityLifecycleBuilder {
    fn default() -> Self {
        Self {
            owner: None,
            registry_identity: None,
            workspace: None,
            limits: None,
            deadline_ms: None,
            clock: None,
            tokens: None,
            durable: None,
            approval: None,
            cancellation: None,
            generation: 1,
        }
    }
}

impl CapabilityLifecycleBuilder {
    pub fn owner(mut self, owner: CapabilityOwner) -> Self {
        self.owner = Some(owner);
        self
    }

    pub fn registry_identity(mut self, identity: impl Into<String>) -> Self {
        self.registry_identity = Some(identity.into());
        self
    }

    pub fn workspace(mut self, workspace: impl Into<PathBuf>) -> Self {
        self.workspace = Some(workspace.into());
        self
    }

    pub fn limits(mut self, limits: LifecycleLimits) -> Self {
        self.limits = Some(limits);
        self
    }

    pub fn deadline_ms(mut self, deadline_ms: u64) -> Self {
        self.deadline_ms = Some(deadline_ms);
        self
    }

    pub fn clock(mut self, clock: Arc<dyn LifecycleClock>) -> Self {
        self.clock = Some(clock);
        self
    }

    pub fn tokens(mut self, tokens: Arc<dyn TokenIssuer>) -> Self {
        self.tokens = Some(tokens);
        self
    }

    pub fn durable(mut self, durable: Arc<dyn DurableToolLifecycle>) -> Self {
        self.durable = Some(durable);
        self
    }

    pub fn approval(mut self, approval: Arc<dyn ApprovalGate>) -> Self {
        self.approval = Some(approval);
        self
    }

    pub fn cancellation(mut self, cancellation: Arc<dyn CancellationFlag>) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    pub fn generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }

    pub fn build(self) -> Result<CapabilityLifecycle, LifecycleError> {
        let owner = self.owner.ok_or_else(|| {
            LifecycleError::InvalidMetadata("lifecycle owner is required".to_string())
        })?;
        let registry_identity = self.registry_identity.ok_or_else(|| {
            LifecycleError::InvalidMetadata("registry identity is required".to_string())
        })?;
        let workspace = self
            .workspace
            .ok_or_else(|| LifecycleError::InvalidMetadata("workspace is required".to_string()))?;
        let limits = self.limits.ok_or_else(|| {
            LifecycleError::InvalidMetadata("lifecycle limits are required".to_string())
        })?;
        if limits.max_tool_calls == 0
            || limits.max_output_bytes == 0
            || limits.max_summary_bytes == 0
        {
            return Err(LifecycleError::InvalidMetadata(
                "lifecycle limits must be positive".to_string(),
            ));
        }
        let deadline_ms = self.deadline_ms.ok_or_else(|| {
            LifecycleError::InvalidMetadata("deadline_ms is required".to_string())
        })?;
        let clock = self
            .clock
            .ok_or_else(|| LifecycleError::InvalidMetadata("clock is required".to_string()))?;
        let tokens = self.tokens.ok_or_else(|| {
            LifecycleError::InvalidMetadata("token issuer is required".to_string())
        })?;
        let durable = self.durable.ok_or_else(|| {
            LifecycleError::InvalidMetadata("durable lifecycle is required".to_string())
        })?;
        let approval = self.approval.ok_or_else(|| {
            LifecycleError::InvalidMetadata("approval gate is required".to_string())
        })?;
        Ok(CapabilityLifecycle {
            inner: Arc::new(LifecycleInner {
                owner,
                registry_identity,
                workspace,
                limits,
                deadline_ms,
                clock,
                tokens,
                durable,
                approval,
                cancellation: self
                    .cancellation
                    .unwrap_or_else(|| Arc::new(NeverCancelled)),
                generation: AtomicU64::new(self.generation),
                call_count: AtomicU64::new(0),
                token_states: Mutex::new(HashMap::new()),
            }),
        })
    }
}

enum TokenState {
    Open {
        claims: Box<TokenClaims>,
        resources: Vec<Arc<dyn TokenOwnedResource>>,
    },
    Committed {
        call_id: String,
    },
    Interrupted {
        call_id: String,
    },
}

/// Resource bound to an open execution token. Released on interrupt, not on commit.
pub(crate) trait TokenOwnedResource: Send + Sync {
    fn release(&self);
}

fn release_resources(resources: Vec<Arc<dyn TokenOwnedResource>>) {
    for resource in resources {
        resource.release();
    }
}

fn token_call_id(state: &TokenState) -> &str {
    match state {
        TokenState::Open { claims, .. } => claims.call_id.as_str(),
        TokenState::Committed { call_id } => call_id.as_str(),
        TokenState::Interrupted { call_id } => call_id.as_str(),
    }
}

struct LifecycleInner {
    owner: CapabilityOwner,
    registry_identity: String,
    workspace: PathBuf,
    limits: LifecycleLimits,
    deadline_ms: u64,
    clock: Arc<dyn LifecycleClock>,
    tokens: Arc<dyn TokenIssuer>,
    durable: Arc<dyn DurableToolLifecycle>,
    approval: Arc<dyn ApprovalGate>,
    cancellation: Arc<dyn CancellationFlag>,
    generation: AtomicU64,
    call_count: AtomicU64,
    token_states: Mutex<HashMap<String, TokenState>>,
}

/// Run-scoped generic tool lifecycle engine.
#[derive(Clone)]
pub struct CapabilityLifecycle {
    inner: Arc<LifecycleInner>,
}

impl CapabilityLifecycle {
    pub fn builder() -> CapabilityLifecycleBuilder {
        CapabilityLifecycleBuilder::default()
    }

    /// Frozen workspace path captured at admission.
    pub fn workspace(&self) -> &Path {
        &self.inner.workspace
    }

    /// Monotonic milliseconds from the admitted clock. Callers cannot forge
    /// this value; they must present an authorized execution token via the
    /// generic host primitive.
    pub fn now_ms(&self) -> u64 {
        self.inner.clock.now_ms()
    }

    pub fn prepare(
        &self,
        owner: &CapabilityOwner,
        metadata: PrepareMetadata,
    ) -> Result<PrepareOutcome, LifecycleError> {
        if owner != &self.inner.owner {
            return Err(LifecycleError::OwnerMismatch {
                expected: self.inner.owner.key(),
                actual: owner.key(),
            });
        }
        if metadata.run_id != self.inner.owner.run() {
            return Err(LifecycleError::OwnerMismatch {
                expected: self.inner.owner.key(),
                actual: self.inner.owner.with_run(&metadata.run_id),
            });
        }
        self.inner.durable.assert_active_run(&metadata.run_id)?;
        self.inner.durable.prepare_parent(
            &metadata.run_id,
            &metadata.call_id,
            &metadata.tool_name,
        )?;
        if let Some(result) = self.inner.durable.replay_result(
            &metadata.run_id,
            &metadata.call_id,
            &metadata.tool_name,
        )? {
            return Ok(PrepareOutcome::Replay { result });
        }
        {
            let unresolved = self
                .inner
                .token_states
                .lock()
                .values()
                .any(|state| token_call_id(state) == metadata.call_id);
            if unresolved {
                return Err(LifecycleError::UnresolvedCall);
            }
        }
        if self.inner.clock.now_ms() >= self.inner.deadline_ms {
            return Err(LifecycleError::DeadlineElapsed);
        }
        if self.inner.cancellation.is_cancelled() {
            return Err(LifecycleError::Cancelled);
        }
        if metadata.registry_identity != self.inner.registry_identity {
            return Err(LifecycleError::RegistryMismatch);
        }
        if metadata.call_id.is_empty() || metadata.tool_name.is_empty() {
            return Err(LifecycleError::InvalidMetadata(
                "call_id and tool name are required".to_string(),
            ));
        }
        if metadata.summary.len() > self.inner.limits.max_summary_bytes {
            return Err(LifecycleError::InvalidMetadata(
                "summary exceeds the configured bound".to_string(),
            ));
        }
        if self.inner.call_count.load(Ordering::SeqCst) >= self.inner.limits.max_tool_calls {
            return Err(LifecycleError::LimitExceeded);
        }
        let ceiling = self.inner.approval.authorize(&metadata)?;
        let generation = self.inner.generation.load(Ordering::SeqCst);
        let record = DurableStarted {
            run_id: metadata.run_id.clone(),
            call_id: metadata.call_id.clone(),
            tool_name: metadata.tool_name.clone(),
            argument_digest: metadata.argument_digest.clone(),
            registry_identity: metadata.registry_identity.clone(),
            risk_class: metadata.risk_class,
            summary: metadata.summary.clone(),
            generation,
        };
        self.inner.durable.commit_started(&record)?;
        let execution_token = self.inner.tokens.issue();
        let remaining_ms = self
            .inner
            .deadline_ms
            .saturating_sub(self.inner.clock.now_ms());
        let deadline = self
            .inner
            .clock
            .now()
            .checked_add(std::time::Duration::from_millis(remaining_ms))
            .unwrap_or_else(|| self.inner.clock.now());
        self.inner.token_states.lock().insert(
            execution_token.clone(),
            TokenState::Open {
                claims: Box::new(TokenClaims {
                    owner: self.inner.owner.clone(),
                    call_id: metadata.call_id,
                    tool_name: metadata.tool_name,
                    argument_digest: metadata.argument_digest,
                    registry_identity: metadata.registry_identity,
                    risk_ceiling: ceiling,
                    output_budget: self.inner.limits.max_output_bytes,
                    generation,
                    deadline,
                    deadline_ms: self.inner.deadline_ms,
                    workspace: self.inner.workspace.clone(),
                }),
                resources: Vec::new(),
            },
        );
        self.inner.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(PrepareOutcome::Execute {
            execution_token,
            deadline_ms: self.inner.deadline_ms,
        })
    }

    pub fn commit(
        &self,
        owner: &CapabilityOwner,
        token: &str,
        result: Value,
    ) -> Result<CommitOutcome, LifecycleError> {
        if owner != &self.inner.owner {
            return Err(LifecycleError::OwnerMismatch {
                expected: self.inner.owner.key(),
                actual: owner.key(),
            });
        }
        let mut states = self.inner.token_states.lock();
        let claims = match states.get(token) {
            Some(TokenState::Open { claims, .. }) => claims.clone(),
            Some(TokenState::Committed { .. }) => return Err(LifecycleError::DuplicateClose),
            Some(TokenState::Interrupted { .. }) => return Err(LifecycleError::Interrupted),
            None => return Err(LifecycleError::TokenUnknown),
        };
        if &claims.owner != owner {
            return Err(LifecycleError::OwnerMismatch {
                expected: claims.owner.key(),
                actual: owner.key(),
            });
        }
        if json_size(&result) > claims.output_budget {
            return Err(LifecycleError::ResultTooLarge);
        }
        if self.inner.clock.now_ms() >= claims.deadline_ms {
            return Err(LifecycleError::DeadlineElapsed);
        }
        if self.inner.cancellation.is_cancelled() {
            return Err(LifecycleError::Cancelled);
        }
        validate_canonical_result(&result)?;
        states.insert(
            token.to_string(),
            TokenState::Committed {
                call_id: claims.call_id.clone(),
            },
        );
        drop(states);
        let committed = self.inner.durable.commit_result(&claims.call_id, &result)?;
        Ok(CommitOutcome {
            envelope: json!({
                "ok": true,
                "kind": "committed",
                "call_id": claims.call_id,
                "result": committed,
            }),
        })
    }

    pub fn lease(&self, token: &str) -> Result<ExecutionLease, LifecycleError> {
        match self.inner.token_states.lock().get(token) {
            Some(TokenState::Open { .. }) => Ok(ExecutionLease {
                lifecycle: self.clone(),
                token: token.to_string(),
                closed: false,
            }),
            Some(TokenState::Committed { .. }) => Err(LifecycleError::DuplicateClose),
            Some(TokenState::Interrupted { .. }) => Err(LifecycleError::Interrupted),
            None => Err(LifecycleError::TokenUnknown),
        }
    }

    /// Lookup and authorize an open execution token before a future `cap::*` effect.
    pub fn authorize(
        &self,
        owner: &CapabilityOwner,
        token: &str,
        requested: CapabilityRisk,
    ) -> Result<TokenClaims, LifecycleError> {
        if owner != &self.inner.owner {
            return Err(LifecycleError::OwnerMismatch {
                expected: self.inner.owner.key(),
                actual: owner.key(),
            });
        }
        if self.inner.cancellation.is_cancelled() {
            return Err(LifecycleError::Cancelled);
        }
        let states = self.inner.token_states.lock();
        let claims = match states.get(token) {
            Some(TokenState::Open { claims, .. }) => claims.as_ref().clone(),
            Some(TokenState::Committed { .. }) => return Err(LifecycleError::DuplicateClose),
            Some(TokenState::Interrupted { .. }) => return Err(LifecycleError::Interrupted),
            None => return Err(LifecycleError::TokenUnknown),
        };
        drop(states);
        if &claims.owner != owner {
            return Err(LifecycleError::OwnerMismatch {
                expected: claims.owner.key(),
                actual: owner.key(),
            });
        }
        if self.inner.clock.now_ms() >= claims.deadline_ms {
            return Err(LifecycleError::DeadlineElapsed);
        }
        if claims.generation != self.inner.generation.load(Ordering::SeqCst) {
            return Err(LifecycleError::Interrupted);
        }
        if requested > claims.risk_ceiling {
            return Err(LifecycleError::ApprovalCeiling {
                requested,
                ceiling: claims.risk_ceiling,
            });
        }
        Ok(claims)
    }

    pub(crate) fn register_resource(
        &self,
        token: &str,
        resource: Arc<dyn TokenOwnedResource>,
    ) -> Result<(), LifecycleError> {
        let mut states = self.inner.token_states.lock();
        match states.get_mut(token) {
            Some(TokenState::Open { resources, .. }) => {
                resources.push(resource);
                Ok(())
            }
            Some(TokenState::Committed { .. }) => Err(LifecycleError::DuplicateClose),
            Some(TokenState::Interrupted { .. }) => {
                drop(states);
                resource.release();
                Err(LifecycleError::Interrupted)
            }
            None => {
                drop(states);
                resource.release();
                Err(LifecycleError::TokenUnknown)
            }
        }
    }

    pub fn recover_open_tokens(&self) -> Result<Vec<String>, LifecycleError> {
        // Eager Interrupted before durable I/O prevents Drop from racing a still-Open
        // token. Durable interrupt failure is returned to the caller; in-process
        // re-prepare is fenced by the Interrupted call_id unless durable replay
        // already exists. Cross-restart repeated effects are Task 0F.
        let mut states = self.inner.token_states.lock();
        let open: Vec<(String, String)> = states
            .iter()
            .filter_map(|(token, state)| match state {
                TokenState::Open { claims, .. } => Some((token.clone(), claims.call_id.clone())),
                TokenState::Committed { .. } | TokenState::Interrupted { .. } => None,
            })
            .collect();
        let mut resources = Vec::new();
        for (token, call_id) in &open {
            if let Some(TokenState::Open {
                resources: owned, ..
            }) = states.insert(
                token.clone(),
                TokenState::Interrupted {
                    call_id: call_id.clone(),
                },
            ) {
                resources.extend(owned);
            }
        }
        drop(states);
        release_resources(resources);
        let mut recovered = Vec::with_capacity(open.len());
        for (_, call_id) in open {
            self.inner.durable.interrupt(&call_id)?;
            recovered.push(call_id);
        }
        self.inner.generation.fetch_add(1, Ordering::SeqCst);
        Ok(recovered)
    }

    fn interrupt_token(&self, token: &str) -> Result<(), LifecycleError> {
        let mut states = self.inner.token_states.lock();
        let call_id = match states.get(token) {
            Some(TokenState::Open { claims, .. }) => claims.call_id.clone(),
            Some(TokenState::Interrupted { .. } | TokenState::Committed { .. }) => return Ok(()),
            None => return Err(LifecycleError::TokenUnknown),
        };
        let resources = match states.insert(
            token.to_string(),
            TokenState::Interrupted {
                call_id: call_id.clone(),
            },
        ) {
            Some(TokenState::Open { resources, .. }) => resources,
            _ => Vec::new(),
        };
        drop(states);
        release_resources(resources);
        self.inner.durable.interrupt(&call_id)
    }
}

/// RAII lease: Drop interrupts an still-open token (panic/unwind cleanup).
pub struct ExecutionLease {
    lifecycle: CapabilityLifecycle,
    token: String,
    closed: bool,
}

impl ExecutionLease {
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Disarm the lease after a successful commit so Drop does not interrupt.
    pub fn disarm(&mut self) {
        self.closed = true;
    }
}

impl Drop for ExecutionLease {
    fn drop(&mut self) {
        if !self.closed {
            self.closed = true;
            let _ = self.lifecycle.interrupt_token(&self.token);
        }
    }
}

fn json_size(value: &Value) -> usize {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
}

fn validate_canonical_result(result: &Value) -> Result<(), LifecycleError> {
    let object = result
        .as_object()
        .ok_or_else(|| LifecycleError::InvalidMetadata("tool result must be a map".to_string()))?;
    let ok = match object.get("ok") {
        Some(Value::Bool(ok)) => *ok,
        Some(_) => {
            return Err(LifecycleError::InvalidMetadata(
                "`ok` must be a boolean".to_string(),
            ));
        }
        None => {
            return Err(LifecycleError::InvalidMetadata(
                "`ok` is required".to_string(),
            ));
        }
    };
    if ok {
        match object.get("content") {
            Some(Value::String(_)) => {}
            _ => {
                return Err(LifecycleError::InvalidMetadata(
                    "success result requires string `content`".to_string(),
                ));
            }
        }
    } else {
        let error = object.get("error").and_then(Value::as_object);
        match error.and_then(|error| error.get("code")) {
            Some(Value::String(code)) if !code.is_empty() => {}
            _ => {
                return Err(LifecycleError::InvalidMetadata(
                    "failure result requires string `error.code`".to_string(),
                ));
            }
        }
        if let Some(error) = error
            && let Some(message) = error.get("message")
            && !message.is_string()
        {
            return Err(LifecycleError::InvalidMetadata(
                "`error.message` must be a string".to_string(),
            ));
        }
        if let Some(content) = object.get("content")
            && !content.is_string()
        {
            return Err(LifecycleError::InvalidMetadata(
                "failure `content` must be a string".to_string(),
            ));
        }
    }
    validate_optional_result_fields(object)
}

fn validate_optional_result_fields(
    object: &serde_json::Map<String, Value>,
) -> Result<(), LifecycleError> {
    if let Some(truncated) = object.get("truncated")
        && !truncated.is_boolean()
    {
        return Err(LifecycleError::InvalidMetadata(
            "`truncated` must be a boolean".to_string(),
        ));
    }
    if let Some(data) = object.get("data")
        && !data.is_object()
    {
        return Err(LifecycleError::InvalidMetadata(
            "`data` must be a map".to_string(),
        ));
    }
    if let Some(artifacts) = object.get("artifacts") {
        let Some(items) = artifacts.as_array() else {
            return Err(LifecycleError::InvalidMetadata(
                "`artifacts` must be an array of strings".to_string(),
            ));
        };
        if items.iter().any(|item| !item.is_string()) {
            return Err(LifecycleError::InvalidMetadata(
                "`artifacts` must be an array of strings".to_string(),
            ));
        }
    }
    Ok(())
}
