//! Real default provider dispatch and native authentication boundaries.

#![cfg(feature = "config-fixture")]

#[path = "support/opaque_chat_stream.rs"]
mod opaque_chat_stream;

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustscript_agent::auth::{
    host::AuthHost,
    oauth::{
        BoundedHttpsTransport, OAuthError, OAuthHost, OAuthIoContext, PreparedHttpsRequest,
        RawHttpsResponse, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
        ScriptedHttpsTransport,
    },
};
use rustscript_agent::{
    AgentConfig, AgentHostBridges, AgentRunner, CancellationReason, RunCancellation,
};
use rustscript_vm::Value;
use serde_json::{Value as JsonValue, json};

/// Outer RSS entry: forward the public request through the production bridge.
/// The default provider (not an injected one) handles dispatch.
const OUTER_SOURCE: &str = r#"
use agent;
pub fn run(context: map) -> map {
    let request: map = context["request"];
    agent::provider_call(request)
}
"#;

struct FixtureHome(PathBuf);

impl FixtureHome {
    fn new() -> Self {
        let root = PathBuf::from(
            std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned fixture temp"),
        );
        let home = root.join(format!("default-opaque-home-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&home).expect("create private fixture home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        let config = fs::read_to_string(fixture.join("config.yaml"))
            .expect("read config fixture")
            .replace("openai-codex", "openai")
            .replace(
                "https://chatgpt.com/backend-api/codex",
                "https://api.openai.com/v1",
            )
            .replace("fixture-codex", "synthetic-openai");
        fs::write(home.join("config.yaml"), config).expect("write private config fixture");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read auth fixture")
            .replace("1788440000000", "1900003600000")
            .replace("openai-codex", "openai")
            .replace("fixture-codex", "synthetic-openai")
            .replace("SYNTHETIC_ACCESS_TOKEN", "SYNTHETIC_OPENAI_ACCESS");
        fs::write(home.join("auth.yaml"), auth).expect("write private auth fixture");
        #[cfg(unix)]
        {
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600))
                    .expect("fixture file mode");
            }
        }
        Self(home)
    }
}

impl Drop for FixtureHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture_factory(
    home: &FixtureHome,
    transport: Arc<dyn BoundedHttpsTransport>,
) -> Arc<dyn Fn(RunCancellation) -> Result<AuthHost, String> + Send + Sync> {
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
        Arc::new(ScriptedCancel::new()),
    ));
    let home_path = home.0.clone();
    Arc::new(move |cancellation: RunCancellation| {
        AuthHost::new(home_path.clone(), cancellation)
            .map(|host| host.with_oauth_host(Arc::clone(&oauth)))
    })
}

/// Outer runner with a native auth host factory and no injected provider.
fn outer_runner(
    home: &FixtureHome,
    transport: Arc<dyn BoundedHttpsTransport>,
    cancellation: RunCancellation,
) -> AgentRunner {
    let bridges = AgentHostBridges {
        auth_host_factory: Some(fixture_factory(home, transport)),
        ..AgentHostBridges::default()
    };
    AgentRunner::from_source(OUTER_SOURCE, AgentConfig::default())
        .expect("compile outer provider bridge source")
        .with_host(bridges)
        .with_cancellation(cancellation)
}

fn json_to_vm_value(value: &JsonValue) -> Value {
    match value {
        JsonValue::Null => Value::Null,
        JsonValue::Bool(value) => Value::Bool(*value),
        JsonValue::Number(value) => {
            if let Some(value) = value.as_i64() {
                Value::Int(value)
            } else {
                Value::Float(value.as_f64().expect("finite JSON number"))
            }
        }
        JsonValue::String(value) => Value::string(value),
        JsonValue::Array(values) => {
            Value::Array(Arc::new(values.iter().map(json_to_vm_value).collect()))
        }
        JsonValue::Object(entries) => Value::map(
            entries
                .iter()
                .map(|(key, value)| (Value::string(key), json_to_vm_value(value)))
                .collect(),
        ),
    }
}

fn vm_value_to_json(value: &Value) -> JsonValue {
    match value {
        Value::Null => JsonValue::Null,
        Value::Int(value) => json!(value),
        Value::Float(value) => serde_json::Number::from_f64(*value)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        Value::Bool(value) => json!(value),
        Value::String(value) => JsonValue::String(value.to_string()),
        Value::Bytes(value) => JsonValue::String(String::from_utf8_lossy(value).into_owned()),
        Value::Array(values) => JsonValue::Array(values.iter().map(vm_value_to_json).collect()),
        Value::Map(entries) => JsonValue::Object(
            entries
                .iter()
                .filter_map(|(key, value)| match key {
                    Value::String(key) => Some((key.to_string(), vm_value_to_json(value))),
                    _ => None,
                })
                .collect(),
        ),
        Value::Callable(_) => JsonValue::String("<callable>".to_string()),
    }
}

fn public_request() -> JsonValue {
    json!({
        "provider": "openai",
        "model": "request-model",
        "stream": false,
        "credential_id": "synthetic-openai",
        "messages": [{
            "role": "user",
            "content": [{"type": "text", "text": "hello default dispatch"}]
        }],
        "tools": [{
            "name": "lookup",
            "description": "Look something up",
            "schema_json": "{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\"}}}"
        }],
        "sampling": {"temperature": 0.25},
        "max_output_tokens": 64,
        // Public hostile authority: the default provider must not honour it.
        "provider_options": {
            "base_url": "http://127.0.0.1:1/must-not-be-used",
            "model": "hostile-public-model"
        }
    })
}

fn context(request: JsonValue) -> Value {
    Value::map(vec![(Value::string("request"), json_to_vm_value(&request))])
}

fn finite() -> RunCancellation {
    RunCancellation::with_timeout(Duration::from_secs(30))
}

/// One canonical OpenAI Chat completion with usage and a tool call.
fn canonical_chat_body() -> JsonValue {
    json!({
        "id": "chatcmpl-default",
        "choices": [{
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "content": "Found one match.",
                "tool_calls": [{
                    "id": "call_default",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": "{\"query\":\"rustscript\"}"}
                }]
            }
        }],
        "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}
    })
}

#[test]
fn default_provider_dispatches_opaque_openai_through_injected_native_auth() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, canonical_chat_body());
    let runner = outer_runner(&home, transport.clone(), finite());

    let result = vm_value_to_json(
        &runner
            .run_with_context(context(public_request()))
            .expect("genuine default provider dispatch completes"),
    );

    assert_eq!(
        result["ok"],
        json!(true),
        "unexpected default result: {result}"
    );
    assert_eq!(result["response"]["text"], json!("Found one match."));
    assert_eq!(result["response"]["stop_reason"], json!("tool_calls"));
    assert_eq!(result["response"]["usage"]["input_tokens"], json!(3));
    assert_eq!(result["response"]["usage"]["output_tokens"], json!(4));
    assert_eq!(result["response"]["usage"]["total_tokens"], json!(7));
    assert_eq!(
        result["response"]["tool_calls"][0]["id"],
        json!("call_default")
    );
    assert_eq!(result["response"]["tool_calls"][0]["name"], json!("lookup"));
    assert_eq!(
        result["response"]["tool_calls"][0]["arguments"]["query"],
        json!("rustscript")
    );

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "exactly one native buffered request");
    assert_eq!(sent[0].method, "POST");
    assert_eq!(
        sent[0].url, "https://api.openai.com/v1/chat/completions",
        "native trusted authority must win over the public hostile base_url"
    );
    assert_eq!(
        sent[0].headers.get("authorization").map(String::as_str),
        Some("Bearer SYNTHETIC_OPENAI_ACCESS")
    );
    assert_eq!(
        sent[0].headers.get("accept").map(String::as_str),
        Some("application/json")
    );
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("public OpenAI wire JSON");
    assert_eq!(wire["model"], json!("request-model"));
    assert_eq!(wire["stream"], json!(false));
    assert_eq!(
        wire["messages"][0]["content"][0]["text"],
        json!("hello default dispatch")
    );
    assert_eq!(wire["temperature"], json!(0.25));
    assert_eq!(wire["max_tokens"], json!(64));

    let rendered = result.to_string();
    for secret in [
        "SYNTHETIC_OPENAI_ACCESS",
        "SYNTHETIC_REFRESH_TOKEN",
        "host_home",
        "hostile-public-model",
    ] {
        assert!(
            !rendered.contains(secret),
            "public canonical result leaked {secret}"
        );
    }
}

#[test]
fn default_provider_redacts_child_auth_setup_failure() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let native_factory = fixture_factory(&home, transport.clone());
    let created = std::sync::atomic::AtomicUsize::new(0);
    let bridges = AgentHostBridges {
        auth_host_factory: Some(Arc::new(move |cancellation| {
            if created.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                native_factory(cancellation)
            } else {
                Err("SYNTHETIC_PRIVATE_FACTORY_DETAIL".to_string())
            }
        })),
        ..AgentHostBridges::default()
    };
    let runner = AgentRunner::from_source(OUTER_SOURCE, AgentConfig::default())
        .expect("compile outer source")
        .with_host(bridges)
        .with_cancellation(finite());
    let result = vm_value_to_json(
        &runner
            .run_with_context(context(public_request()))
            .expect("child setup failure returns a public envelope"),
    );
    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["error"]["code"], json!("adapter_failed"));
    assert!(
        !result
            .to_string()
            .contains("SYNTHETIC_PRIVATE_FACTORY_DETAIL"),
        "child setup details must not be published: {result}"
    );
    assert!(transport.take_sent().is_empty());
}

#[test]
fn default_provider_without_native_auth_factory_fails_closed_without_transport() {
    // No factory installed: the default provider must fail closed statically.
    let runner = AgentRunner::from_source(OUTER_SOURCE, AgentConfig::default())
        .expect("compile outer source without factory")
        .with_cancellation(finite());

    let result = vm_value_to_json(
        &runner
            .run_with_context(context(public_request()))
            .expect("static fail-closed envelope"),
    );
    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["error"]["code"], json!("auth_unavailable"));
}

#[test]
fn default_provider_unadmitted_credential_is_canonical_and_sends_nothing() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let runner = outer_runner(&home, transport.clone(), finite());
    let mut request = public_request();
    request["credential_id"] = json!("not-admitted");

    let result = vm_value_to_json(
        &runner
            .run_with_context(context(request))
            .expect("unadmitted reference returns a canonical public failure"),
    );
    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["error"]["code"], json!("credential_not_admitted"));
    assert!(transport.take_sent().is_empty());
    assert!(!result.to_string().contains("SYNTHETIC_OPENAI_ACCESS"));
}

#[test]
fn default_provider_missing_credential_is_canonical_and_sends_nothing() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let runner = outer_runner(&home, transport.clone(), finite());
    let mut request = public_request();
    request["credential_id"] = json!("");

    let result = vm_value_to_json(
        &runner
            .run_with_context(context(request))
            .expect("missing credential reference returns a canonical public failure"),
    );
    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["error"]["code"], json!("missing_credential"));
    assert!(transport.take_sent().is_empty());
}

#[test]
fn default_provider_guards_unsupported_provider_and_private_options_without_start() {
    use opaque_chat_stream::StreamTransport;
    use std::sync::atomic::Ordering;
    let cases: [(&str, bool, JsonValue, &str); 3] = [
        (
            "unsupported-provider",
            false,
            json!("anthropic"),
            "adapter_unavailable",
        ),
        (
            "private-options",
            false,
            json!({"api_key": "SYNTHETIC_PRIVATE_OPTION_MARKER"}),
            "config",
        ),
        (
            "private-options-stream",
            true,
            json!({"api_key": "SYNTHETIC_PRIVATE_OPTION_MARKER"}),
            "config",
        ),
    ];

    for (label, stream, mutation, expected_code) in cases {
        let home = FixtureHome::new();
        let transport = Arc::new(StreamTransport::new(
            200,
            "text/event-stream",
            vec![b"data: [DONE]\n\n".to_vec()],
            false,
        ));
        let runner = outer_runner(&home, transport.clone(), finite());
        let mut request = public_request();
        request["stream"] = json!(stream);
        if label == "unsupported-provider" {
            request["provider"] = mutation;
        } else {
            request["provider_options"] = mutation;
        }

        let result = vm_value_to_json(&runner.run_with_context(context(request)).unwrap_or_else(
            |error| panic!("{label} guard must return a canonical value: {error}"),
        ));
        assert_eq!(result["ok"], json!(false), "{label} guard must fail closed");
        assert_eq!(result["error"]["code"], json!(expected_code), "{label}");
        assert_eq!(
            transport.counts.starts.load(Ordering::SeqCst),
            0,
            "{label} guard must not start a stream"
        );
        assert!(
            transport
                .counts
                .sent
                .lock()
                .expect("recorded native request")
                .is_empty(),
            "{label} guard must not reach the native transport"
        );
        assert!(
            !result
                .to_string()
                .contains("SYNTHETIC_PRIVATE_OPTION_MARKER")
        );
    }
}

#[test]
fn default_provider_stream_credential_guards_start_nothing() {
    use opaque_chat_stream::StreamTransport;
    use std::sync::atomic::Ordering;
    let cases: [(&str, &str); 2] = [
        ("", "missing_credential"),
        ("not-admitted", "credential_not_admitted"),
    ];
    for (credential, expected_code) in cases {
        let home = FixtureHome::new();
        let transport = Arc::new(StreamTransport::new(
            200,
            "text/event-stream",
            vec![b"data: [DONE]\n\n".to_vec()],
            false,
        ));
        let runner = outer_runner(&home, transport.clone(), finite());
        let mut request = public_request();
        request["stream"] = json!(true);
        request["credential_id"] = json!(credential);
        let result = vm_value_to_json(&runner.run_with_context(context(request)).unwrap_or_else(
            |error| panic!("credential guard must return a canonical value: {error}"),
        ));
        assert_eq!(result["ok"], json!(false), "{expected_code}");
        assert_eq!(result["error"]["code"], json!(expected_code));
        assert_eq!(
            transport.counts.starts.load(Ordering::SeqCst),
            0,
            "credential guard must not start a stream"
        );
        assert!(
            transport
                .counts
                .sent
                .lock()
                .expect("recorded native request")
                .is_empty()
        );
        assert!(!result.to_string().contains("SYNTHETIC_OPENAI_ACCESS"));
    }
}

/// Blocks inside the native transport until the child observes the inherited
/// caller cancellation, proving the child invocation is bounded by the parent.
struct PendingCancelTransport {
    entered: std::sync::mpsc::SyncSender<()>,
}

impl BoundedHttpsTransport for PendingCancelTransport {
    fn send(
        &self,
        _request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        self.entered.send(()).map_err(|_| OAuthError::Transport {
            message: "pending test observer closed".to_string(),
        })?;
        loop {
            context.check()?;
            thread::sleep(Duration::from_millis(2));
        }
    }
}

#[test]
fn default_provider_child_inherits_caller_finite_cancellation() {
    let home = FixtureHome::new();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let transport: Arc<dyn BoundedHttpsTransport> = Arc::new(PendingCancelTransport {
        entered: entered_tx,
    });
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(10));
    let runner = outer_runner(&home, transport, cancellation.clone());

    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let result = runner.run_with_context(context(public_request()));
        let _ = result_tx.send(result);
    });

    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("child native transport must be entered");
    cancellation.request(CancellationReason::Requested);

    let outcome = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("inherited cancellation must terminate the run within the bound");
    match outcome {
        Ok(result) => {
            let result = vm_value_to_json(&result);
            assert_eq!(result["ok"], json!(false));
            let code = result["error"]["code"].clone();
            assert!(
                code == json!("cancelled") || code == json!("deadline_elapsed"),
                "unexpected inherited cancellation code: {code}"
            );
        }
        Err(error) => {
            let rendered = error.to_string();
            assert!(
                rendered.contains("cancel") || rendered.contains("deadline"),
                "unexpected inherited cancellation failure: {error}"
            );
        }
    }
    worker.join().expect("cancellation worker join");
}

#[test]
fn default_provider_dispatches_opaque_openai_stream_with_indexed_tool_fragments() {
    use opaque_chat_stream::StreamTransport;
    use std::sync::atomic::Ordering;
    let home = FixtureHome::new();
    let transport = Arc::new(StreamTransport::new(
        200,
        "text/event-stream",
        vec![concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Found \"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"one match.\"},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_default\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{\\\"qu\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_default\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"ery\\\":\\\"rustscript\\\"}\"}}]}}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4,\"total_tokens\":7}}\n\n",
            "data: [DONE]\n\n"
        )
        .as_bytes()
        .to_vec()],
        false,
    ));
    let runner = outer_runner(&home, transport.clone(), finite());
    let mut request = public_request();
    request["stream"] = json!(true);
    let result = vm_value_to_json(&runner.run_with_context(context(request)).unwrap_or_else(
        |error| {
            panic!(
                "default dispatch stream failed: {error}; starts={}, drops={}",
                transport.counts.starts.load(Ordering::SeqCst),
                transport.counts.drops.load(Ordering::SeqCst)
            )
        },
    ));
    assert_eq!(
        result["ok"],
        json!(true),
        "unexpected default stream result: {result}"
    );
    assert_eq!(result["response"]["text"], json!("Found one match."));
    assert_eq!(result["response"]["stop_reason"], json!("tool_calls"));
    assert_eq!(result["response"]["usage"]["input_tokens"], json!(3));
    assert_eq!(result["response"]["usage"]["output_tokens"], json!(4));
    assert_eq!(result["response"]["usage"]["total_tokens"], json!(7));
    assert_eq!(
        result["response"]["tool_calls"][0]["id"],
        json!("call_default")
    );
    assert_eq!(result["response"]["tool_calls"][0]["name"], json!("lookup"));
    assert_eq!(
        result["response"]["tool_calls"][0]["arguments"]["query"],
        json!("rustscript"),
        "indexed tool fragments must accumulate: {result}"
    );
    assert_eq!(transport.counts.starts.load(Ordering::SeqCst), 1);
    assert_eq!(transport.counts.reads.load(Ordering::SeqCst), 1);
    assert_eq!(transport.counts.eof.load(Ordering::SeqCst), 0);
    assert_eq!(transport.counts.cancels.load(Ordering::SeqCst), 1);
    assert_eq!(transport.counts.drops.load(Ordering::SeqCst), 1);

    let sent = transport.counts.sent.lock().expect("native request");
    assert_eq!(sent.len(), 1, "exactly one admitted stream start");
    assert_eq!(sent[0].method, "POST");
    assert_eq!(
        sent[0].url, "https://api.openai.com/v1/chat/completions",
        "native trusted authority must win over the public hostile base_url"
    );
    assert!(
        sent[0]
            .headers
            .get("authorization")
            .is_some_and(|value| value == "Bearer SYNTHETIC_OPENAI_ACCESS"),
        "native authorization must match the stored synthetic credential"
    );
    assert_eq!(
        sent[0].headers.get("accept").map(String::as_str),
        Some("text/event-stream")
    );
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("public stream body");
    assert_eq!(wire["model"], json!("request-model"));
    assert_eq!(wire["stream"], json!(true));
    assert_eq!(wire["stream_options"]["include_usage"], json!(true));
    assert_eq!(wire["temperature"], json!(0.25));
    assert_eq!(wire["max_tokens"], json!(64));
    assert_eq!(
        wire["messages"][0]["content"][0]["text"],
        json!("hello default dispatch")
    );
    assert_eq!(wire["tools"][0]["type"], json!("function"));
    assert_eq!(wire["tools"][0]["function"]["name"], json!("lookup"));
    assert_eq!(
        wire["tools"][0]["function"]["parameters"],
        json!({"type":"object","properties":{"query":{"type":"string"}}}),
        "tool schema must be spliced raw into the stream body"
    );
    drop(sent);

    let rendered = result.to_string();
    for secret in [
        "SYNTHETIC_OPENAI_ACCESS",
        "SYNTHETIC_REFRESH_TOKEN",
        "host_home",
        "hostile-public-model",
    ] {
        assert!(
            !rendered.contains(secret),
            "public canonical result leaked {secret}"
        );
    }
}
