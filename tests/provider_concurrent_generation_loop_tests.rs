//! Concurrent refresh adoption through the production main/default/native loop.
#![cfg(feature = "config-fixture")]
#[path = "support/provider_opaque_fixture.rs"]
#[allow(dead_code)]
pub mod provider_opaque_fixture;
use provider_opaque_fixture::{FixtureHome, json_to_vm_value, vm_value_to_json};
use rustscript_agent::auth::oauth::{
    BoundedHttpsTransport, OAuthError, OAuthIoContext, PreparedHttpsRequest, RawHttpsResponse,
};
use rustscript_agent::{AgentConfig, AgentHostBridges, AgentRunner, RunCancellation};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

const ID: &str = "synthetic-openai";
const OLD: &str = "SYNTHETIC_ORIGINAL_ACCESS";
const WIN_ACCESS: &str = "SYNTHETIC_WINNER_ACCESS";
const WIN_REFRESH: &str = "SYNTHETIC_WINNER_REFRESH";
const LATE_ACCESS: &str = "SYNTHETIC_LATE_ACCESS";
const LATE_REFRESH: &str = "SYNTHETIC_LATE_REFRESH";

#[derive(Default)]
struct Recorded {
    tokens: Vec<PreparedHttpsRequest>,
    models: Vec<PreparedHttpsRequest>,
    winner_model_arrived: bool,
}
#[derive(Default)]
struct DelayedRefreshTransport {
    recorded: Mutex<Recorded>,
    changed: Condvar,
}
impl DelayedRefreshTransport {
    fn wait<'a>(
        &'a self,
        mut state: std::sync::MutexGuard<'a, Recorded>,
        context: &OAuthIoContext,
        ready: impl Fn(&Recorded) -> bool,
    ) -> Result<std::sync::MutexGuard<'a, Recorded>, OAuthError> {
        let end = Instant::now() + Duration::from_secs(8);
        while !ready(&state) {
            context.check()?;
            let remaining = end.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(OAuthError::Transport {
                    message: "concurrent_refresh_wait_expired".into(),
                });
            }
            state = self
                .changed
                .wait_timeout(state, remaining.min(Duration::from_millis(50)))
                .expect("recorded transport mutex")
                .0;
        }
        context.check()?;
        Ok(state)
    }
}
fn response(body: Value) -> RawHttpsResponse {
    RawHttpsResponse {
        status: 200,
        headers: BTreeMap::new(),
        body: serde_json::to_vec(&body).expect("response JSON"),
    }
}
impl BoundedHttpsTransport for DelayedRefreshTransport {
    fn send(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        context.check()?;
        let mut state = self.recorded.lock().expect("recorded transport mutex");
        if request.url.ends_with("/oauth/token") {
            let ticket = state.tokens.len();
            state.tokens.push(request.clone());
            self.changed.notify_all();
            state = self.wait(state, context, |s| s.tokens.len() >= 2)?;
            // Both requests are already on the wire with the original generation.
            // Hold the late response until the first owner saved and sent its model.
            if ticket == 1 {
                state = self.wait(state, context, |s| s.winner_model_arrived)?;
            }
            drop(state);
            let (access, refresh) = if ticket == 0 {
                (WIN_ACCESS, WIN_REFRESH)
            } else {
                (LATE_ACCESS, LATE_REFRESH)
            };
            return Ok(response(
                json!({"access_token": access, "refresh_token": refresh, "expires_in": 3600, "token_type": "Bearer"}),
            ));
        }
        if request.url.ends_with("/v1/chat/completions") {
            state.models.push(request.clone());
            state.winner_model_arrived = true;
            self.changed.notify_all();
            drop(state);
            return Ok(response(
                json!({"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "shared generation answer"}}]}),
            ));
        }
        Err(OAuthError::Transport {
            message: "unexpected_concurrent_refresh_endpoint".into(),
        })
    }
}
fn real_loop(home: &FixtureHome, transport: Arc<DelayedRefreshTransport>) -> Value {
    let runner = AgentRunner::from_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent/main.rss"),
        AgentConfig::default(),
    )
    .expect("compile actual main")
    .with_host(AgentHostBridges {
        auth_host_factory: Some(home.auth_factory(transport)),
        ..AgentHostBridges::default()
    })
    .with_skip_sleep(true)
    .with_cancellation(RunCancellation::with_timeout(Duration::from_secs(30)));
    vm_value_to_json(
        &runner
            .run_with_context(json_to_vm_value(&json!({
                "credential_id": ID, "provider": "openai", "model": "requested-model",
                "input": {"message": "same public request"}, "config": {"max_retries": 2},
                "limits": {"max_turns": 8, "max_tool_calls": 8}
            })))
            .expect("actual main decision"),
    )
}
#[test]
fn late_refresh_response_adopts_winner_and_fresh_loop_reuses_persisted_auth() {
    let home = FixtureHome::for_profile(
        "concurrent-generation",
        "openai",
        "https://api.openai.com/v1",
        ID,
        OLD,
    )
    .with_expiry(ID, 1_899_999_999_999);
    let before = home.stored_auth();
    let transport = Arc::new(DelayedRefreshTransport::default());
    let decisions = std::thread::scope(|scope| {
        let first = scope.spawn(|| real_loop(&home, transport.clone()));
        let second = scope.spawn(|| real_loop(&home, transport.clone()));
        [
            first.join().expect("first real loop"),
            second.join().expect("second real loop"),
        ]
    });
    for decision in &decisions {
        assert!(
            decision["kind"] == json!("run.completed"),
            "main loop did not complete"
        );
        assert!(
            decision["answer"] == json!("shared generation answer"),
            "main loop answer changed"
        );
        assert!(
            decision["retry_count"] == json!(0),
            "main loop retried unexpectedly"
        );
        for secret in [OLD, WIN_ACCESS, WIN_REFRESH, LATE_ACCESS, LATE_REFRESH] {
            assert!(!decision.to_string().contains(secret));
        }
    }
    let state = transport.recorded.lock().expect("recorded transport mutex");
    assert_eq!(state.tokens.len(), 2);
    assert_eq!(state.models.len(), 2);
    for token in &state.tokens {
        assert_eq!(token.url, "https://api.openai.com/oauth/token");
        assert_eq!(token.method, "POST");
        assert!(token.body.contains("grant_type=refresh_token"));
    }
    assert!(
        state.tokens[0].body == state.tokens[1].body,
        "refresh request bodies differed"
    );
    for model in &state.models {
        assert_eq!(model.url, "https://api.openai.com/v1/chat/completions");
        assert_eq!(model.method, "POST");
        assert!(
            model
                .headers
                .get("authorization")
                .is_some_and(|v| v == &format!("Bearer {WIN_ACCESS}"))
        );
        let public: Value = serde_json::from_str(&model.body).expect("public model JSON");
        assert_eq!(public["model"], json!("requested-model"));
        for secret in [OLD, WIN_ACCESS, WIN_REFRESH, LATE_ACCESS, LATE_REFRESH] {
            assert!(!model.body.contains(secret));
        }
    }
    assert!(
        state.models[0].body == state.models[1].body,
        "concurrent model request bodies differed"
    );
    let expected_model_body = state.models[0].body.clone();
    let after = home.stored_auth();
    let saved = &after["credentials"][ID];
    assert_eq!(
        saved["generation"].as_i64(),
        before["credentials"][ID]["generation"]
            .as_i64()
            .map(|v| v + 1)
    );
    assert!(saved["access_token"].as_str() == Some(WIN_ACCESS));
    assert!(saved["refresh_token"].as_str() == Some(WIN_REFRESH));
    drop(state);

    // This is a new logical run, not a durable-replay check.
    let fresh_decision = real_loop(&home, transport.clone());
    assert!(
        fresh_decision["kind"] == json!("run.completed"),
        "fresh loop did not complete"
    );
    assert!(
        fresh_decision["answer"] == json!("shared generation answer"),
        "fresh loop answer changed"
    );
    assert!(
        fresh_decision["retry_count"] == json!(0),
        "fresh loop retried unexpectedly"
    );
    for secret in [OLD, WIN_ACCESS, WIN_REFRESH, LATE_ACCESS, LATE_REFRESH] {
        assert!(!fresh_decision.to_string().contains(secret));
    }

    let state = transport.recorded.lock().expect("recorded transport mutex");
    assert_eq!(state.tokens.len(), 2);
    assert_eq!(state.models.len(), 3);
    let fresh_model = &state.models[2];
    assert_eq!(
        fresh_model.url,
        "https://api.openai.com/v1/chat/completions"
    );
    assert_eq!(fresh_model.method, "POST");
    assert!(
        fresh_model
            .headers
            .get("authorization")
            .is_some_and(|v| v == &format!("Bearer {WIN_ACCESS}"))
    );
    assert!(
        fresh_model.body == expected_model_body,
        "fresh model request body changed"
    );
    let public: Value = serde_json::from_str(&fresh_model.body).expect("fresh public model JSON");
    assert_eq!(public["model"], json!("requested-model"));
    for secret in [OLD, WIN_ACCESS, WIN_REFRESH, LATE_ACCESS, LATE_REFRESH] {
        assert!(!fresh_model.body.contains(secret));
    }
    drop(state);
    assert!(
        home.stored_auth() == after,
        "persisted auth YAML changed after the fresh run"
    );
}
