#![cfg(feature = "config-fixture")]

#[path = "support/opaque_chat_stream.rs"]
mod opaque_chat_stream;

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustscript_agent::auth::{
    host::AuthHost,
    oauth::{
        BoundedHttpsTransport, OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel,
        ScriptedClock, ScriptedHttpsTransport,
    },
};
use rustscript_agent::{AgentConfig, AgentHostBridges, AgentRunner, RunCancellation};
use rustscript_vm::Value;
use serde_json::{Value as JsonValue, json};

struct FixtureHome(PathBuf);

impl FixtureHome {
    fn new() -> Self {
        let root = PathBuf::from(
            std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned fixture temp"),
        );
        let home = root.join(format!("openai-opaque-home-{}", uuid::Uuid::new_v4()));
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

fn fixture_runner<T: BoundedHttpsTransport + 'static>(
    home: &FixtureHome,
    transport: Arc<T>,
) -> AgentRunner {
    fixture_runner_with_clock(
        home,
        transport,
        Arc::new(ScriptedClock::new(1_900_000_000_000)),
    )
}

fn fixture_runner_with_clock<T: BoundedHttpsTransport + 'static>(
    home: &FixtureHome,
    transport: Arc<T>,
    clock: Arc<ScriptedClock>,
) -> AgentRunner {
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        clock,
        Arc::new(ScriptedCancel::new()),
    ));
    let home_path = home.0.clone();
    let factory = Arc::new(move |cancellation: RunCancellation| {
        AuthHost::new(home_path.clone(), cancellation)
            .map(|host| host.with_oauth_host(Arc::clone(&oauth)))
    });
    let bridges = AgentHostBridges {
        auth_host_factory: Some(factory),
        ..AgentHostBridges::default()
    };
    AgentRunner::from_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/llm/openai_opaque_chat.rss"),
        AgentConfig::default(),
    )
    .expect("compile production opaque OpenAI Chat entry")
    .with_host(bridges)
    .with_cancellation(RunCancellation::with_timeout(Duration::from_secs(30)))
}

fn context(request: JsonValue, profile: JsonValue, credential_id: &str) -> Value {
    Value::map(vec![
        (Value::string("request"), json_to_vm_value(&request)),
        (Value::string("profile"), json_to_vm_value(&profile)),
        (Value::string("credential_id"), Value::string(credential_id)),
    ])
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

fn canonical_request() -> JsonValue {
    json!({
        "model": "request-model",
        "stream": false,
        "messages": [{
            "role": "user",
            "content": [{"type": "text", "text": "hello opaque Chat"}]
        }],
        "tools": [{
            "name": "lookup",
            "description": "Look something up",
            "schema_json": "{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\"}}}"
        }],
        "sampling": {"temperature": 0.25},
        "max_output_tokens": 64
    })
}

#[test]
fn opaque_openai_chat_uses_native_auth_and_returns_canonical_text_usage_and_tool_calls() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(
        200,
        json!({
            "id": "chatcmpl-fixture",
            "choices": [{
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": "Found one match.",
                    "tool_calls": [{
                        "id": "call_fixture",
                        "type": "function",
                        "function": {"name": "lookup", "arguments": "{\"query\":\"rustscript\"}"}
                    }]
                }
            }],
            "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}
        }),
    );
    let runner = fixture_runner(&home, Arc::clone(&transport));
    let result = vm_value_to_json(
        &runner
            .run_with_context(context(
                canonical_request(),
                json!({
                    "provider": "openai",
                    "base_url": "https://profile-authority.invalid/must-not-be-used",
                    "model": "profile-model-is-already-resolved"
                }),
                "synthetic-openai",
            ))
            .expect("opaque Chat call should complete"),
    );

    assert_eq!(
        result["ok"],
        json!(true),
        "expected a parsed canonical OpenAI Chat response, got {result}"
    );
    assert_eq!(result["response"]["text"], json!("Found one match."));
    assert_eq!(result["response"]["stop_reason"], json!("tool_calls"));
    assert_eq!(result["response"]["usage"]["input_tokens"], json!(3));
    assert_eq!(result["response"]["usage"]["output_tokens"], json!(4));
    assert_eq!(result["response"]["usage"]["total_tokens"], json!(7));
    assert_eq!(
        result["response"]["tool_calls"][0]["id"],
        json!("call_fixture")
    );
    assert_eq!(result["response"]["tool_calls"][0]["name"], json!("lookup"));
    assert_eq!(
        result["response"]["tool_calls"][0]["arguments"]["query"],
        json!("rustscript")
    );

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "exactly one native buffered request");
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[0].url, "https://api.openai.com/v1/chat/completions");
    assert_eq!(
        sent[0].headers.get("authorization").map(String::as_str),
        Some("Bearer SYNTHETIC_OPENAI_ACCESS")
    );
    assert_eq!(
        sent[0].headers.get("accept").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(
        sent[0].headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("public OpenAI wire JSON");
    assert_eq!(wire["model"], json!("request-model"));
    assert_eq!(wire["stream"], json!(false));
    assert_eq!(
        wire["messages"][0]["content"][0]["text"],
        json!("hello opaque Chat")
    );
    assert_eq!(
        wire["tools"][0]["function"]["parameters"]["type"],
        json!("object")
    );
    assert_eq!(wire["temperature"], json!(0.25));
    assert_eq!(wire["max_tokens"], json!(64));
    let rendered = result.to_string();
    for secret in [
        "SYNTHETIC_OPENAI_ACCESS",
        "SYNTHETIC_REFRESH_TOKEN",
        "host_home",
    ] {
        assert!(
            !rendered.contains(secret),
            "public canonical result leaked {secret}"
        );
    }
}

fn public_profile() -> JsonValue {
    json!({
        "provider": "openai",
        "base_url": "https://profile-authority.invalid/must-not-be-used",
        "model": "profile-model-is-already-resolved"
    })
}

fn run_request(
    home: &FixtureHome,
    transport: Arc<ScriptedHttpsTransport>,
    request: JsonValue,
) -> JsonValue {
    let runner = fixture_runner(home, transport);
    vm_value_to_json(
        &runner
            .run_with_context(context(request, public_profile(), "synthetic-openai"))
            .expect("opaque Chat request should return a canonical value"),
    )
}

#[test]
fn opaque_openai_chat_maps_http_4xx_with_existing_sanitized_error_codec() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(
        400,
        json!({"error": {
            "type": "invalid_request_error",
            "code": "bad_request",
            "message": "Synthetic request rejected",
            "param": "messages",
            "request_id": "req_fixture"
        }}),
    );
    let result = run_request(&home, Arc::clone(&transport), canonical_request());

    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["error"]["status"], json!(400));
    assert_eq!(result["error"]["type"], json!("invalid_request_error"));
    // Native sanitization removes provider `code` fields before RSS sees the body.
    assert_eq!(result["error"]["code"], json!("http_error"));
    assert_eq!(
        result["error"]["message"],
        json!("Synthetic request rejected")
    );
    assert_eq!(result["error"]["param"], json!("messages"));
    assert_eq!(result["error"]["request_id"], json!("req_fixture"));
    assert_eq!(transport.take_sent().len(), 1);
    assert!(!result.to_string().contains("SYNTHETIC_OPENAI_ACCESS"));
}

#[test]
fn opaque_openai_chat_maps_malformed_bounded_protocol_payload() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_json(200, json!({"id": "bounded-but-incomplete"}));
    let result = run_request(&home, Arc::clone(&transport), canonical_request());

    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["error"]["status"], json!(200));
    assert_eq!(result["error"]["type"], json!("malformed_payload"));
    assert_eq!(result["error"]["code"], json!("malformed_payload"));
    assert_eq!(transport.take_sent().len(), 1);
}

#[test]
fn opaque_openai_chat_rejects_missing_model_before_native_send() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let mut request = canonical_request();
    request["model"] = json!("");
    let result = run_request(&home, Arc::clone(&transport), request);

    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["error"]["code"], json!("missing_model"));
    assert!(transport.take_sent().is_empty());
}

#[test]
fn opaque_chat_stream_guards_reject_before_any_start() {
    use opaque_chat_stream::StreamTransport;
    use std::sync::atomic::Ordering;
    let cases: [(&str, &str, Option<JsonValue>, &str); 3] = [
        ("empty-credential", "", None, "credential_not_admitted"),
        (
            "unadmitted-credential",
            "not-admitted",
            None,
            "credential_not_admitted",
        ),
        (
            "private-options",
            "synthetic-openai",
            Some(json!({"api_key": "SYNTHETIC_PRIVATE_OPTION_MARKER"})),
            "config",
        ),
    ];
    for (label, credential, private_options, expected) in cases {
        let home = FixtureHome::new();
        let transport = Arc::new(StreamTransport::new(
            200,
            "text/event-stream",
            vec![b"data: [DONE]\n\n".to_vec()],
            false,
        ));
        let runner = fixture_runner(&home, Arc::clone(&transport));
        let mut request = canonical_request();
        request["stream"] = json!(true);
        if let Some(options) = private_options {
            request["provider_options"] = options;
        }
        let result = vm_value_to_json(
            &runner
                .run_with_context(context(request, public_profile(), credential))
                .unwrap_or_else(|error| {
                    panic!("{label} guard must return a canonical value: {error}")
                }),
        );
        assert_eq!(result["ok"], json!(false), "{label} guard must fail closed");
        assert_eq!(result["error"]["code"], json!(expected), "{label}");
        assert_eq!(
            transport.counts.starts.load(Ordering::SeqCst),
            0,
            "{label} must not start a stream"
        );
        assert!(
            transport
                .counts
                .sent
                .lock()
                .expect("recorded native request")
                .is_empty(),
            "{label} must not reach the native transport"
        );
        let rendered = result.to_string();
        assert!(!rendered.contains("SYNTHETIC_OPENAI_ACCESS"), "{label}");
        assert!(
            !rendered.contains("SYNTHETIC_PRIVATE_OPTION_MARKER"),
            "{label}"
        );
    }
}

#[test]
fn opaque_chat_stream_eof_without_done_after_partial_text_fails_closed() {
    use opaque_chat_stream::StreamTransport;
    use std::sync::atomic::Ordering;
    let home = FixtureHome::new();
    let transport = Arc::new(StreamTransport::new(
        200,
        "text/event-stream",
        vec![
            b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial text\"}}]}\n\n"
                .to_vec(),
        ],
        true,
    ));
    let runner = fixture_runner(&home, Arc::clone(&transport));
    let mut request = canonical_request();
    request["stream"] = json!(true);
    let result = vm_value_to_json(
        &runner
            .run_with_context(context(request, public_profile(), "synthetic-openai"))
            .expect("EOF without DONE must return a canonical public failure"),
    );
    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["error"]["code"], json!("stream_eof_without_done"));
    assert_ne!(
        result["response"]["text"],
        json!("partial text"),
        "EOF without DONE must never publish partial success"
    );
    assert_eq!(transport.counts.starts.load(Ordering::SeqCst), 1);
    assert!(transport.counts.drops.load(Ordering::SeqCst) >= 1);
}

#[test]
fn opaque_chat_stream_semantic_invalid_object_is_static_public_failure() {
    use opaque_chat_stream::StreamTransport;
    use std::sync::atomic::Ordering;
    let home = FixtureHome::new();
    let transport = Arc::new(StreamTransport::new(
        200,
        "text/event-stream",
        vec![b"data: {\"id\":\"bounded-but-incomplete\"}\n\n".to_vec()],
        false,
    ));
    let runner = fixture_runner(&home, Arc::clone(&transport));
    let mut request = canonical_request();
    request["stream"] = json!(true);
    let result = vm_value_to_json(
        &runner
            .run_with_context(context(request, public_profile(), "synthetic-openai"))
            .expect("semantic stream failure must stay a canonical public value"),
    );
    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["error"]["code"], json!("malformed_payload"));
    assert!(
        !result.to_string().contains("bounded-but-incomplete"),
        "the offending stream object must not be echoed: {result}"
    );
    assert_eq!(transport.counts.starts.load(Ordering::SeqCst), 1);
    assert!(transport.counts.drops.load(Ordering::SeqCst) >= 1);
}

#[test]
fn opaque_chat_stream_non_json_record_fails_closed_without_echo() {
    use opaque_chat_stream::StreamTransport;
    use std::sync::atomic::Ordering;
    let home = FixtureHome::new();
    let transport = Arc::new(StreamTransport::new(
        200,
        "text/event-stream",
        vec![b"data: not-strict-json\n\n".to_vec()],
        false,
    ));
    let runner = fixture_runner(&home, Arc::clone(&transport));
    let mut request = canonical_request();
    request["stream"] = json!(true);
    let result = vm_value_to_json(
        &runner
            .run_with_context(context(request, public_profile(), "synthetic-openai"))
            .expect("strict non-JSON record must stay a canonical public value"),
    );
    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["error"]["code"], json!("malformed_response"));
    assert!(
        !result.to_string().contains("not-strict-json"),
        "raw stream data must not be echoed: {result}"
    );
    assert_eq!(transport.counts.starts.load(Ordering::SeqCst), 1);
    assert!(transport.counts.drops.load(Ordering::SeqCst) >= 1);
}

#[test]
fn opaque_chat_stream_injected_read_failure_detail_is_not_echoed() {
    use opaque_chat_stream::StreamTransport;
    use std::sync::atomic::Ordering;
    let home = FixtureHome::new();
    let transport = Arc::new(
        StreamTransport::new(200, "text/event-stream", Vec::new(), false)
            .with_read_error("SYNTHETIC_PRIVATE_READ_DETAIL"),
    );
    let runner = fixture_runner(&home, Arc::clone(&transport));
    let mut request = canonical_request();
    request["stream"] = json!(true);
    let result = vm_value_to_json(
        &runner
            .run_with_context(context(request, public_profile(), "synthetic-openai"))
            .expect("injected transport read failure must stay a canonical public value"),
    );
    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["error"]["code"], json!("transport_error"));
    assert_eq!(
        result["error"]["message"],
        json!("provider transport failed")
    );
    assert!(
        !result.to_string().contains("SYNTHETIC_PRIVATE_READ_DETAIL"),
        "injected transport detail must not be published: {result}"
    );
    assert_eq!(transport.counts.starts.load(Ordering::SeqCst), 1);
    assert!(transport.counts.drops.load(Ordering::SeqCst) >= 1);
}

#[test]
fn opaque_chat_stream_http_errors_use_existing_status_classification() {
    use opaque_chat_stream::StreamTransport;
    use std::sync::atomic::Ordering;
    let cases: [(u16, &str, bool); 2] = [
        (401, "invalid_request_error", false),
        (429, "rate_limit_error", true),
    ];
    for (status, error_type, retryable) in cases {
        let home = FixtureHome::new();
        let body = json!({
            "error": {
                "type": error_type,
                "code": "SYNTHETIC_PRIVATE_CODE_FIELD",
                "message": "Synthetic provider rejection",
                "api_key": "SYNTHETIC_PRIVATE_OPTION_MARKER"
            }
        });
        let transport = Arc::new(StreamTransport::new(
            status,
            "application/json",
            vec![body.to_string().into_bytes()],
            true,
        ));
        let runner = fixture_runner(&home, Arc::clone(&transport));
        let mut request = canonical_request();
        request["stream"] = json!(true);
        let result = vm_value_to_json(
            &runner
                .run_with_context(context(request, public_profile(), "synthetic-openai"))
                .unwrap_or_else(|error| {
                    panic!("HTTP {status} must return a public failure: {error}")
                }),
        );
        assert_eq!(result["ok"], json!(false), "HTTP {status}");
        assert_eq!(result["error"]["status"], json!(status), "HTTP {status}");
        assert_eq!(result["error"]["type"], json!(error_type), "HTTP {status}");
        assert_eq!(
            result["error"]["code"],
            json!("http_error"),
            "HTTP {status}"
        );
        assert_eq!(
            result["error"]["retryable"],
            json!(retryable),
            "HTTP {status} retryability"
        );
        assert_eq!(
            result["error"]["message"],
            json!("Synthetic provider rejection"),
            "HTTP {status}"
        );
        assert_eq!(
            transport.counts.starts.load(Ordering::SeqCst),
            1,
            "HTTP {status} must start exactly once with no retry"
        );
        assert!(
            transport.counts.drops.load(Ordering::SeqCst) >= 1,
            "HTTP {status} must close the stream resource"
        );
        let rendered = result.to_string();
        assert!(
            !rendered.contains("SYNTHETIC_PRIVATE_CODE_FIELD"),
            "HTTP {status}"
        );
        assert!(
            !rendered.contains("SYNTHETIC_PRIVATE_OPTION_MARKER"),
            "HTTP {status}"
        );
        assert!(
            !rendered.contains("SYNTHETIC_OPENAI_ACCESS"),
            "HTTP {status}"
        );
    }
}

#[test]
fn opaque_chat_stream_unsupported_mime_fails_closed_without_echo() {
    use opaque_chat_stream::StreamTransport;
    use std::sync::atomic::Ordering;
    let home = FixtureHome::new();
    let transport = Arc::new(StreamTransport::new(
        200,
        "text/plain",
        vec![b"data: {\"choices\":[]}\n\n".to_vec()],
        true,
    ));
    let runner = fixture_runner(&home, Arc::clone(&transport));
    let mut request = canonical_request();
    request["stream"] = json!(true);
    let result = vm_value_to_json(
        &runner
            .run_with_context(context(request, public_profile(), "synthetic-openai"))
            .expect("unsupported MIME must stay a canonical public value"),
    );
    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["error"]["code"], json!("malformed_response"));
    assert!(
        !result.to_string().contains("text/plain"),
        "raw media type must not be published: {result}"
    );
    assert_eq!(transport.counts.starts.load(Ordering::SeqCst), 1);
    assert!(transport.counts.drops.load(Ordering::SeqCst) >= 1);
}

#[test]
fn opaque_chat_stream_deadline_expiry_during_live_stream_has_no_partial_success() {
    use opaque_chat_stream::StreamTransport;
    use std::sync::atomic::Ordering;
    let home = FixtureHome::new();
    let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
    let transport = Arc::new(
        StreamTransport::new(
            200,
            "text/event-stream",
            vec![
                b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial text\"}}]}\n\n"
                    .to_vec(),
            ],
            false,
        )
        .with_read_callback({
            let clock = Arc::clone(&clock);
            move || clock.expire()
        }),
    );
    let runner = fixture_runner_with_clock(&home, Arc::clone(&transport), clock);
    let mut request = canonical_request();
    request["stream"] = json!(true);
    let result = vm_value_to_json(
        &runner
            .run_with_context(context(request, public_profile(), "synthetic-openai"))
            .expect("stream expiry must stay a canonical public value"),
    );
    assert_eq!(result["ok"], json!(false));
    let code = result["error"]["code"].clone();
    assert!(
        code == json!("deadline_exceeded") || code == json!("cancelled"),
        "unexpected stream expiry code: {code}"
    );
    assert_ne!(
        result["response"]["text"],
        json!("partial text"),
        "expiry during a live stream must never publish partial success"
    );
    assert_eq!(
        transport.counts.starts.load(Ordering::SeqCst),
        1,
        "expiry must not trigger a second start"
    );
    assert!(transport.counts.drops.load(Ordering::SeqCst) >= 1);
}

#[test]
fn opaque_openai_chat_rejects_private_provider_options_without_send_or_echo() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let mut request = canonical_request();
    request["provider_options"] = json!({"api_key": "SYNTHETIC_PRIVATE_OPTION_MARKER"});
    let result = run_request(&home, Arc::clone(&transport), request);

    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["error"]["code"], json!("config"));
    assert!(transport.take_sent().is_empty());
    assert!(
        !result
            .to_string()
            .contains("SYNTHETIC_PRIVATE_OPTION_MARKER")
    );
}

#[test]
fn opaque_openai_chat_native_policy_denial_is_safe_and_sends_nothing() {
    let home = FixtureHome::new();
    let config_path = home.0.join("config.yaml");
    let config = fs::read_to_string(&config_path)
        .expect("read fixture config")
        .replace("https://api.openai.com/v1", "https://api.openai.com/v2");
    fs::write(&config_path, config).expect("restrict fixture trusted path");
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let result = run_request(&home, Arc::clone(&transport), canonical_request());

    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["error"]["code"], json!("path_denied"));
    assert_eq!(
        result["error"]["message"],
        json!("provider transport failed")
    );
    assert!(transport.take_sent().is_empty());
    let rendered = result.to_string();
    for secret in [
        "SYNTHETIC_OPENAI_ACCESS",
        "SYNTHETIC_REFRESH_TOKEN",
        "host_home",
    ] {
        assert!(!rendered.contains(secret));
    }
}

#[test]
fn opaque_openai_chat_preserves_unadmitted_credential_failure_without_send() {
    let home = FixtureHome::new();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let runner = fixture_runner(&home, Arc::clone(&transport));
    let result = vm_value_to_json(
        &runner
            .run_with_context(context(
                canonical_request(),
                public_profile(),
                "not-admitted",
            ))
            .expect("metadata rejection returns a canonical public failure"),
    );
    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["error"]["code"], json!("credential_not_admitted"));
    assert_eq!(
        result["error"]["message"],
        json!("provider transport failed")
    );
    assert!(transport.take_sent().is_empty());
    assert!(!result.to_string().contains("SYNTHETIC_OPENAI_ACCESS"));
}

#[test]
fn opaque_chat_stream_json_array_is_public_failure_and_closes_reader() {
    use opaque_chat_stream::StreamTransport;
    use std::sync::atomic::Ordering;
    let home = FixtureHome::new();
    let transport = Arc::new(StreamTransport::new(
        200,
        "text/event-stream",
        vec![b"data: [1,2]\n\n".to_vec()],
        false,
    ));
    let runner = fixture_runner(&home, Arc::clone(&transport));
    let mut request = canonical_request();
    request["stream"] = json!(true);
    let result = vm_value_to_json(
        &runner
            .run_with_context(context(
                request,
                json!({"provider":"openai"}),
                "synthetic-openai",
            ))
            .expect("valid JSON array must yield public failure, not VM abort"),
    );
    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["error"]["code"], json!("malformed_payload"));
    assert_eq!(transport.counts.starts.load(Ordering::SeqCst), 1);
    assert_eq!(transport.counts.reads.load(Ordering::SeqCst), 1);
    assert_eq!(transport.counts.eof.load(Ordering::SeqCst), 0);
    assert_eq!(transport.counts.cancels.load(Ordering::SeqCst), 1);
    assert_eq!(transport.counts.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn opaque_chat_stream_finishes_before_eof_with_native_auth() {
    use opaque_chat_stream::StreamTransport;
    use std::sync::atomic::Ordering;
    let home = FixtureHome::new();
    let transport = Arc::new(StreamTransport::new(
        200, "text/event-stream",
        vec![concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\" stream\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4,\"total_tokens\":7}}\n\n",
            "data: [DONE]\n\n"
        ).as_bytes().to_vec()], false,
    ));
    let runner = fixture_runner(&home, Arc::clone(&transport));
    let mut request = canonical_request();
    request["stream"] = json!(true);
    let result = vm_value_to_json(
        &runner
            .run_with_context(context(
                request,
                json!({"provider":"openai","base_url":"https://ignored.invalid"}),
                "synthetic-openai",
            ))
            .unwrap_or_else(|error| {
                panic!(
                    "stream call failed: {error}; starts={}, reads={}, drops={}",
                    transport.counts.starts.load(Ordering::SeqCst),
                    transport.counts.reads.load(Ordering::SeqCst),
                    transport.counts.drops.load(Ordering::SeqCst)
                )
            }),
    );
    assert_eq!(
        result["ok"],
        json!(true),
        "stream call must succeed; public code={}",
        result["error"]["code"]
    );
    assert_eq!(result["response"]["text"], json!("Hello stream"));
    assert_eq!(result["response"]["usage"]["total_tokens"], json!(7));
    assert_eq!(transport.counts.starts.load(Ordering::SeqCst), 1);
    assert_eq!(transport.counts.reads.load(Ordering::SeqCst), 1);
    assert_eq!(transport.counts.eof.load(Ordering::SeqCst), 0);
    assert_eq!(transport.counts.cancels.load(Ordering::SeqCst), 1);
    assert_eq!(transport.counts.drops.load(Ordering::SeqCst), 1);
    let sent = transport.counts.sent.lock().expect("native request");
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[0].url, "https://api.openai.com/v1/chat/completions");
    assert!(
        sent[0]
            .headers
            .get("authorization")
            .is_some_and(|s| s == "Bearer SYNTHETIC_OPENAI_ACCESS"),
        "native authorization must match stored synthetic credential"
    );
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("public stream body");
    assert_eq!(wire["stream"], json!(true));
    assert_eq!(wire["stream_options"]["include_usage"], json!(true));
    assert_eq!(
        wire["messages"][0]["content"][0]["text"],
        json!("hello opaque Chat")
    );
    assert!(!result.to_string().contains("SYNTHETIC_OPENAI_ACCESS"));
}
