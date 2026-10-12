//! Provider protocol adapter tests through native auth.
//!
//! Each test compiles the production RSS adapter modules (through the generic
//! `rss/llm/harness.rss` entry, or the `rss/llm/provider_dispatch.rss` entry
//! for default-alias coverage) and drives them with an `AuthHostFactory` plus
//! an injected counted `BoundedHttpsTransport`. No live network, no raw
//! localhost TCP fixtures, no secret material in requests, profiles, or
//! options: the trusted fixture home owns the HTTPS authority, the native
//! transport owns credentials and the wire, and the recorded native request
//! (method, URL, headers, body) proves the public contract. Real provider
//! transcripts still come from `tests/fixtures/providers/`.

#[path = "support/opaque_chat_stream.rs"]
mod opaque_chat_stream;

#[path = "support/provider_opaque_fixture.rs"]
pub mod provider_opaque_fixture;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustscript_agent::auth::oauth::{BoundedHttpsTransport, ScriptedHttpsTransport};
use rustscript_agent::{
    AgentConfig, AgentHostBridges, AgentRunner, CancellationReason, RunCancellation,
    RunDeliveryError, RunEventSink,
};
use rustscript_vm::Value;
use serde_json::{Value as JsonValue, json};

use provider_opaque_fixture::{
    FixtureHome, canonical_request, harness_context, harness_runner,
    harness_runner_with_cancellation, harness_runner_with_clock, read_provider_fixture, sse_events,
    vm_value_to_json,
};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn response_of(result: &JsonValue) -> &serde_json::Map<String, JsonValue> {
    result["response"].as_object().expect("response object")
}

fn error_of(result: &JsonValue) -> &serde_json::Map<String, JsonValue> {
    result["error"].as_object().expect("error object")
}

/// Runs the production harness entry and renders the canonical result. The
/// entry is addressed by name: the harness tree also contains the opaque
/// Chat entry's canonical `run`, and the runner resolves bare entry names
/// through the flattened exported-callable table (first match wins), so the
/// harness entry is deliberately not named `run`.
fn run_harness(
    runner: &AgentRunner,
    kind: &str,
    request: JsonValue,
    profile: JsonValue,
    credential_id: &str,
) -> JsonValue {
    let context = harness_context(kind, request, profile, credential_id);
    let mut sink = DiscardSink;
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    vm_value_to_json(
        &runner
            .run_named_with_context_and_events("run_harness", context, &mut sink, &cancellation)
            .unwrap_or_else(|error| panic!("harness {kind} run failed: {error:?}")),
    )
}

/// Public profile request: the named credential travels inside the request,
/// the top-level context reference stays empty (fallback path).
fn profile_request(options: JsonValue, model: &str, credential: &str, stream: bool) -> JsonValue {
    let mut request = canonical_request(stream);
    request["provider_options"] = options;
    request["model"] = json!(model);
    request["credential_id"] = json!(credential);
    request
}

/// One synthetic provider endpoint: trusted base, expected logical path
/// intent, named credential, and stored access marker.
struct ProfileEndpoint {
    provider: &'static str,
    kind: &'static str,
    base: &'static str,
    origin: &'static str,
    intent: &'static str,
    credential: &'static str,
    access: &'static str,
}

const PROFILES: [ProfileEndpoint; 5] = [
    ProfileEndpoint {
        provider: "custom",
        origin: "https://fixture-custom.example.test",
        kind: "profile:custom",
        base: "https://fixture-custom.example.test/custom/v1",
        intent: "/custom/v1/chat/completions",
        credential: "synthetic-custom",
        access: "SYNTHETIC_CUSTOM_ACCESS",
    },
    ProfileEndpoint {
        provider: "deepseek",
        origin: "https://fixture-deepseek.example.test",
        kind: "profile:deepseek",
        base: "https://fixture-deepseek.example.test",
        intent: "/chat/completions",
        credential: "synthetic-deepseek",
        access: "SYNTHETIC_DEEPSEEK_ACCESS",
    },
    ProfileEndpoint {
        provider: "opencode_go",
        origin: "https://fixture-go.example.test",
        kind: "profile:opencode_go",
        base: "https://fixture-go.example.test/go/v1",
        intent: "/go/v1/chat/completions",
        credential: "synthetic-go",
        access: "SYNTHETIC_GO_ACCESS",
    },
    ProfileEndpoint {
        provider: "opencode_zen",
        origin: "https://fixture-zen.example.test",
        kind: "profile:opencode_zen",
        base: "https://fixture-zen.example.test/zen/v1",
        intent: "/zen/v1/chat/completions",
        credential: "synthetic-zen",
        access: "SYNTHETIC_ZEN_ACCESS",
    },
    ProfileEndpoint {
        provider: "openrouter",
        origin: "https://fixture-openrouter.example.test",
        kind: "profile:openrouter",
        base: "https://fixture-openrouter.example.test/api/v1",
        intent: "/api/v1/chat/completions",
        credential: "synthetic-openrouter",
        access: "SYNTHETIC_OPENROUTER_ACCESS",
    },
];

fn profile_home(endpoint: &ProfileEndpoint) -> FixtureHome {
    FixtureHome::for_profile(
        endpoint.provider,
        endpoint.provider,
        endpoint.base,
        endpoint.credential,
        endpoint.access,
    )
}

fn openai_home() -> FixtureHome {
    FixtureHome::for_profile(
        "openai",
        "openai",
        "https://fixture.example.test/v1",
        "synthetic-openai",
        "SYNTHETIC_OPENAI_ACCESS",
    )
}

fn openai_profile() -> JsonValue {
    json!({
        "provider": "openai",
        "base_url": "https://fixture.example.test/v1",
        "model": "fixture-model",
    })
}

const PUBLIC_PROFILE_CREDENTIAL_KEYS: [&str; 8] = [
    "api_key",
    "authorization",
    "token",
    "access_token",
    "refresh_token",
    "headers",
    "cookie",
    "cookies",
];

struct DiscardSink;

impl RunEventSink for DiscardSink {
    fn deliver(&mut self, _value: Value) -> Result<(), RunDeliveryError> {
        Ok(())
    }
}

/// Production default-dispatch runner: the `dispatch` entry with native auth.
fn dispatch_runner<T: BoundedHttpsTransport + 'static>(
    home: &FixtureHome,
    transport: Arc<T>,
) -> AgentRunner {
    let bridges = AgentHostBridges {
        auth_host_factory: Some(home.auth_factory(transport)),
        ..AgentHostBridges::default()
    };
    AgentRunner::from_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/llm/provider_dispatch.rss"),
        AgentConfig::default(),
    )
    .expect("production provider dispatch should compile")
    .with_host(bridges)
    .with_cancellation(RunCancellation::with_timeout(Duration::from_secs(30)))
}

fn run_dispatch(runner: &AgentRunner, request: JsonValue) -> JsonValue {
    let context = Value::map(vec![(
        Value::string("request"),
        provider_opaque_fixture::json_to_vm_value(&request),
    )]);
    let mut sink = DiscardSink;
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    vm_value_to_json(
        &runner
            .run_named_with_context_and_events("dispatch", context, &mut sink, &cancellation)
            .unwrap_or_else(|error| panic!("dispatch run failed: {error:?}")),
    )
}

// ---------------------------------------------------------------------------
// Public profile wrappers
// ---------------------------------------------------------------------------

fn assert_profile_rejects_credentials(endpoint: &ProfileEndpoint) {
    let home = profile_home(endpoint);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let runner = harness_runner(&home, Arc::clone(&transport));
    let mut failures = Vec::new();
    for key in PUBLIC_PROFILE_CREDENTIAL_KEYS {
        let secret = format!("synthetic-{}-{key}", endpoint.provider);
        let options = json!({
            "base_url": endpoint.base,
            "model": "public-profile-model",
            key: secret,
        });
        let request = profile_request(options, "public-profile-model", endpoint.credential, false);
        let result = run_harness(&runner, endpoint.kind, request, json!({}), "");
        let error = error_of(&result);
        let rendered = result.to_string();
        let rejected = error.get("code").and_then(JsonValue::as_str) == Some("config")
            && error.get("message").and_then(JsonValue::as_str)
                == Some("credential-bearing provider options are not public");
        if !rejected || rendered.contains(&secret) {
            failures.push(format!("{key}: rejected={rejected}"));
        }
        if !transport.take_sent().is_empty() {
            failures.push(format!("{key}: native transport was reached"));
        }
    }
    assert!(
        failures.is_empty(),
        "credential options were not rejected as specified: {failures:?}"
    );
}

#[test]
fn public_profile_custom_rejects_credentials_before_send() {
    assert_profile_rejects_credentials(&PROFILES[0]);
}

#[test]
fn public_profile_deepseek_rejects_credentials_before_send() {
    assert_profile_rejects_credentials(&PROFILES[1]);
}

#[test]
fn public_profile_opencode_go_rejects_credentials_before_send() {
    assert_profile_rejects_credentials(&PROFILES[2]);
}

#[test]
fn public_profile_opencode_zen_rejects_credentials_before_send() {
    assert_profile_rejects_credentials(&PROFILES[3]);
}

#[test]
fn public_profile_openrouter_rejects_credentials_before_send() {
    assert_profile_rejects_credentials(&PROFILES[4]);
}

#[test]
fn public_profile_nonsecret_overrides_reach_real_wire() {
    let body: JsonValue = serde_json::from_str(&read_provider_fixture("openai_chat/response.json"))
        .expect("chat response fixture should be JSON");
    let expected_model = "public-profile-model-override";
    let mut failures = Vec::new();
    for endpoint in PROFILES {
        let home = profile_home(&endpoint);
        let transport = Arc::new(ScriptedHttpsTransport::new());
        transport.push_json(200, body.clone());
        let runner = harness_runner(&home, Arc::clone(&transport));
        let mut options = json!({"base_url": endpoint.base, "model": expected_model});
        if endpoint.provider == "custom" {
            options["adapter"] = json!("openai_chat");
        }
        let request = profile_request(
            options,
            "request-model-before-profile-override",
            endpoint.credential,
            false,
        );
        let result = run_harness(&runner, endpoint.kind, request, json!({}), "");
        if result["ok"] != json!(true) {
            failures.push(format!("{}: expected ok, got {result}", endpoint.provider));
            continue;
        }
        let sent = transport.take_sent();
        if sent.len() != 1 {
            failures.push(format!(
                "{}: native sends={}",
                endpoint.provider,
                sent.len()
            ));
            continue;
        }
        let expected_url = format!("{}{}", endpoint.origin, endpoint.intent);
        if sent[0].url != expected_url {
            failures.push(format!(
                "{}: trusted url={} intent={}",
                endpoint.provider, sent[0].url, endpoint.intent
            ));
        }
        if sent[0].headers.get("authorization").map(String::as_str)
            != Some(format!("Bearer {}", endpoint.access).as_str())
        {
            failures.push(format!(
                "{}: native authorization mismatch",
                endpoint.provider
            ));
        }
        match serde_json::from_str::<JsonValue>(&sent[0].body) {
            Ok(wire) if wire["model"] == json!(expected_model) => {}
            _ => failures.push(format!(
                "{}: wire model did not use the public profile override",
                endpoint.provider
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "public profile wire mismatches: {failures:?}"
    );
}

#[test]
fn public_profile_request_model_preserved_without_override() {
    let body: JsonValue = serde_json::from_str(&read_provider_fixture("openai_chat/response.json"))
        .expect("chat response fixture should be JSON");
    let canonical_model = "canonical-request-model";
    let mut failures = Vec::new();
    for endpoint in PROFILES {
        for explicit_empty in [false, true] {
            let home = profile_home(&endpoint);
            let transport = Arc::new(ScriptedHttpsTransport::new());
            transport.push_json(200, body.clone());
            let runner = harness_runner(&home, Arc::clone(&transport));
            let mut options = json!({"base_url": endpoint.base});
            if endpoint.provider == "custom" {
                options["adapter"] = json!("openai_chat");
            }
            if explicit_empty {
                options["model"] = json!("");
            }
            let request = profile_request(options, canonical_model, endpoint.credential, false);
            let result = run_harness(&runner, endpoint.kind, request, json!({}), "");
            if result["ok"] != json!(true) {
                failures.push(format!(
                    "{}/empty={explicit_empty}: expected ok, got {result}",
                    endpoint.provider
                ));
                continue;
            }
            let sent = transport.take_sent();
            match sent.first() {
                Some(prepared)
                    if serde_json::from_str::<JsonValue>(&prepared.body)
                        .map(|wire| wire["model"] == json!(canonical_model))
                        .unwrap_or(false) => {}
                _ => failures.push(format!(
                    "{}/empty={explicit_empty}: wire model did not preserve the request model",
                    endpoint.provider
                )),
            }
        }
    }
    assert!(
        failures.is_empty(),
        "public profile request model mismatches: {failures:?}"
    );
}

#[test]
fn public_profile_custom_selects_deferred_adapters_without_send() {
    for adapter in ["anthropic_messages", "openai_responses"] {
        let home = profile_home(&PROFILES[0]);
        let transport = Arc::new(ScriptedHttpsTransport::new());
        let runner = harness_runner(&home, Arc::clone(&transport));
        let options = json!({
            "base_url": PROFILES[0].base,
            "model": "public-profile-model",
            "adapter": adapter,
        });
        let request = profile_request(options, "request-model", PROFILES[0].credential, false);
        let result = run_harness(&runner, "profile:custom", request, json!({}), "");
        assert_eq!(result["ok"], json!(false), "{adapter}");
        assert_eq!(
            error_of(&result)["code"],
            json!("not_implemented"),
            "{adapter}"
        );
        assert!(
            transport.take_sent().is_empty(),
            "{adapter}: stub adapter must not send"
        );
    }
}

#[test]
fn public_profile_hostile_base_never_overrides_native_authority() {
    // A hostile profile base whose path intent escapes the admitted prefix
    // fails closed with zero sends.
    let home = openai_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let runner = harness_runner(&home, Arc::clone(&transport));
    let profile = json!({
        "provider": "openai",
        "base_url": "https://hostile.example.test/evil",
        "model": "fixture-model",
    });
    let result = run_harness(
        &runner,
        "openai_chat",
        canonical_request(false),
        profile,
        "synthetic-openai",
    );
    assert_eq!(result["ok"], json!(false));
    assert_eq!(error_of(&result)["code"], json!("path_denied"));
    assert!(transport.take_sent().is_empty());

    // A hostile authority on an admitted path shape still sends only to the
    // trusted fixture authority: the public base contributes path intent,
    // never transport authority.
    let home = profile_home(&PROFILES[1]);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let body: JsonValue = serde_json::from_str(&read_provider_fixture("openai_chat/response.json"))
        .expect("chat response fixture should be JSON");
    transport.push_json(200, body);
    let runner = harness_runner(&home, Arc::clone(&transport));
    let options = json!({
        "base_url": "https://hostile.example.test/evil",
        "model": "public-profile-model",
    });
    let request = profile_request(options, "request-model", PROFILES[1].credential, false);
    let result = run_harness(&runner, "profile:deepseek", request, json!({}), "");
    assert_eq!(result["ok"], json!(true), "{result}");
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].url, "https://fixture-deepseek.example.test/evil/chat/completions",
        "hostile authority must never override the trusted native authority"
    );
}

#[test]
fn public_profile_missing_credential_fails_closed_without_send() {
    let home = profile_home(&PROFILES[4]);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let runner = harness_runner(&home, Arc::clone(&transport));
    let mut request = canonical_request(false);
    request["provider_options"] = json!({"base_url": PROFILES[4].base});
    let result = run_harness(&runner, "profile:openrouter", request, json!({}), "");
    assert_eq!(result["ok"], json!(false));
    assert_eq!(error_of(&result)["code"], json!("missing_credential"));
    assert!(transport.take_sent().is_empty());
}

// ---------------------------------------------------------------------------
// S1: OpenAI Chat Completions, buffered (native auth)
// ---------------------------------------------------------------------------

#[test]
fn openai_chat_non_stream_text_usage_and_reasoning() {
    let home = openai_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let body: JsonValue = serde_json::from_str(&read_provider_fixture("openai_chat/response.json"))
        .expect("chat response fixture should be JSON");
    transport.push_json(200, body);
    let runner = harness_runner(&home, Arc::clone(&transport));

    let result = run_harness(
        &runner,
        "openai_chat",
        canonical_request(false),
        openai_profile(),
        "synthetic-openai",
    );

    assert!(result["ok"] == json!(true), "{result}");
    let response = response_of(&result);
    assert_eq!(
        response["text"],
        json!("The RustScript agent framework keeps provider policy in RSS.")
    );
    assert_eq!(
        response["reasoning"],
        json!("User asked about the framework; summarize the ownership boundary.")
    );
    assert_eq!(response["stop_reason"], json!("stop"));
    assert_eq!(response["usage"]["input_tokens"], json!(12));
    assert_eq!(response["usage"]["output_tokens"], json!(15));
    assert_eq!(response["usage"]["total_tokens"], json!(27));
    assert_eq!(response["tool_calls"], json!([]));

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "exactly one native buffered request");
    assert_eq!(sent[0].method, "POST");
    assert_eq!(
        sent[0].url, "https://fixture.example.test/v1/chat/completions",
        "native trusted authority owns the request URL"
    );
    assert_eq!(
        sent[0].headers.get("authorization").map(String::as_str),
        Some("Bearer SYNTHETIC_OPENAI_ACCESS")
    );
    assert_eq!(
        sent[0].headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("wire body is JSON");
    assert_eq!(wire["model"], json!("test-model"));
    assert_eq!(wire["stream"], json!(false));
    assert_eq!(wire["max_tokens"], json!(128));
    assert_eq!(wire["temperature"], json!(0.7));
    assert_eq!(wire["messages"][0]["role"], json!("user"));
    assert_eq!(wire["messages"][0]["content"][0]["text"], json!("hello"));
    assert_eq!(wire["messages"][1]["role"], json!("tool"));
    assert_eq!(wire["messages"][1]["tool_call_id"], json!("call_ab12"));
    assert_eq!(wire["messages"][1]["content"], json!("ok"));
    assert_eq!(wire["messages"][2]["role"], json!("assistant"));
    assert_eq!(
        wire["messages"][2]["content"],
        json!("Let me read the file.")
    );
    assert_eq!(
        wire["messages"][2]["tool_calls"][0]["function"]["arguments"],
        json!("{\"path\":\"README.md\"}")
    );
    assert_eq!(
        wire["tools"][0]["function"]["parameters"]["required"][0],
        json!("path")
    );
    assert!(!result.to_string().contains("SYNTHETIC_OPENAI_ACCESS"));
}

#[test]
fn openai_chat_unknown_finish_reason_is_preserved_as_text_response() {
    let home = openai_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let mut body: JsonValue =
        serde_json::from_str(&read_provider_fixture("openai_chat/response.json"))
            .expect("fixture json");
    body["choices"][0]["finish_reason"] = json!("mystery_stop");
    transport.push_json(200, body);
    let runner = harness_runner(&home, Arc::clone(&transport));

    let result = run_harness(
        &runner,
        "openai_chat",
        canonical_request(false),
        openai_profile(),
        "synthetic-openai",
    );

    assert!(result["ok"] == json!(true), "{result}");
    let response = response_of(&result);
    assert_eq!(response["stop_reason"], json!("mystery_stop"));
    assert_eq!(response["tool_calls"], json!([]));
    assert!(
        !response["text"].as_str().expect("text").is_empty(),
        "{response:?}"
    );
}

#[test]
fn openai_chat_non_stream_tool_calls() {
    let home = openai_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let body = read_provider_fixture("openai_chat/response_tools.json");
    transport.push_json(
        200,
        serde_json::from_str(&body).expect("tool response fixture should be JSON"),
    );
    let runner = harness_runner(&home, Arc::clone(&transport));

    let result = run_harness(
        &runner,
        "openai_chat",
        canonical_request(false),
        openai_profile(),
        "synthetic-openai",
    );

    assert!(result["ok"] == json!(true), "{result}");
    let response = response_of(&result);
    assert_eq!(response["text"], json!(""));
    assert_eq!(response["stop_reason"], json!("tool_calls"));
    assert_eq!(response["usage"]["total_tokens"], json!(30));
    let calls = response["tool_calls"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0]["id"], json!("call_ab12"));
    assert_eq!(calls[0]["name"], json!("read_file"));
    assert_eq!(calls[0]["arguments"]["path"], json!("README.md"));
    assert_eq!(calls[0]["arguments"]["lines"], json!(40));
    assert_eq!(calls[1]["id"], json!("call_cd34"));
    assert_eq!(calls[1]["name"], json!("search_files"));
    assert_eq!(calls[1]["arguments"]["pattern"], json!("provider"));
    assert_eq!(transport.take_sent().len(), 1);
}

#[test]
fn openai_chat_provider_error_is_structured() {
    let home = openai_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let body: JsonValue = serde_json::from_str(&read_provider_fixture("openai_chat/error.json"))
        .expect("error fixture should be JSON");
    transport.push_json(400, body);
    let runner = harness_runner(&home, Arc::clone(&transport));

    let result = run_harness(
        &runner,
        "openai_chat",
        canonical_request(false),
        openai_profile(),
        "synthetic-openai",
    );

    assert!(result["ok"] == json!(false), "{result}");
    let error = error_of(&result);
    assert_eq!(error["status"], json!(400));
    assert_eq!(error["type"], json!("invalid_request_error"));
    // Native sanitization removes the provider `code` field before RSS sees
    // the body; the stable public code is the transport HTTP mapping.
    assert_eq!(error["code"], json!("http_error"));
    assert_eq!(error["param"], json!("model"));
    assert!(
        error["message"]
            .as_str()
            .expect("message")
            .contains("does not exist")
    );
    assert_eq!(transport.take_sent().len(), 1);
    assert!(!result.to_string().contains("SYNTHETIC_OPENAI_ACCESS"));
}

#[test]
fn openai_chat_unauthorized_and_rate_limited_are_structured() {
    // 401 denies without retry; 429 admits retry. Both stay canonical with
    // the provider `code` field sanitized away and no secret echo.
    let cases: [(u16, &str, bool); 2] = [
        (401, "invalid_request_error", false),
        (429, "rate_limit_error", true),
    ];
    for (status, error_type, retryable) in cases {
        let home = openai_home();
        let transport = Arc::new(ScriptedHttpsTransport::new());
        transport.push_json(
            status,
            json!({"error": {
                "type": error_type,
                "code": "SYNTHETIC_PRIVATE_CODE_FIELD",
                "message": "Synthetic provider rejection",
                "param": "model",
            }}),
        );
        let runner = harness_runner(&home, Arc::clone(&transport));
        let result = run_harness(
            &runner,
            "openai_chat",
            canonical_request(false),
            openai_profile(),
            "synthetic-openai",
        );
        assert_eq!(result["ok"], json!(false), "HTTP {status}");
        let error = error_of(&result);
        assert_eq!(error["status"], json!(status), "HTTP {status}");
        assert_eq!(error["type"], json!(error_type), "HTTP {status}");
        assert_eq!(error["code"], json!("http_error"), "HTTP {status}");
        assert_eq!(error["retryable"], json!(retryable), "HTTP {status}");
        assert_eq!(
            error["message"],
            json!("Synthetic provider rejection"),
            "HTTP {status}"
        );
        assert_eq!(transport.take_sent().len(), 1, "HTTP {status}");
        let rendered = result.to_string();
        assert!(
            !rendered.contains("SYNTHETIC_PRIVATE_CODE_FIELD"),
            "HTTP {status}"
        );
        assert!(
            !rendered.contains("SYNTHETIC_OPENAI_ACCESS"),
            "HTTP {status}"
        );
    }
}

/// P1 wire-format guard: the recorded native request must carry the standard
/// OpenAI chat-completions wire shape (user `content` as a parts array,
/// tool/assistant content as plain strings, no custom `content_parts` field,
/// tool schemas spliced in place, `tool_choice` omitted when empty). The
/// fixture replies 400 so the run follows the structured error path; the wire
/// is built and recorded before the response is parsed.
#[test]
fn openai_chat_wire_format_is_standard() {
    let home = openai_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let body: JsonValue = serde_json::from_str(&read_provider_fixture("openai_chat/error.json"))
        .expect("error fixture should be JSON");
    transport.push_json(400, body);
    let runner = harness_runner(&home, Arc::clone(&transport));

    let result = run_harness(
        &runner,
        "openai_chat",
        canonical_request(false),
        openai_profile(),
        "synthetic-openai",
    );

    assert!(result["ok"] == json!(false), "{result}");

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].url,
        "https://fixture.example.test/v1/chat/completions"
    );
    assert_eq!(
        sent[0].headers.get("authorization").map(String::as_str),
        Some("Bearer SYNTHETIC_OPENAI_ACCESS")
    );
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("wire body is JSON");

    assert!(
        !sent[0].body.contains("content_parts"),
        "wire must not contain the custom content_parts field: {}",
        sent[0].body
    );
    assert_eq!(wire["messages"][0]["role"], json!("user"));
    assert_eq!(wire["messages"][0]["content"][0]["type"], json!("text"));
    assert_eq!(wire["messages"][0]["content"][0]["text"], json!("hello"));
    assert_eq!(wire["messages"][1]["role"], json!("tool"));
    assert_eq!(wire["messages"][1]["tool_call_id"], json!("call_ab12"));
    assert_eq!(wire["messages"][1]["content"], json!("ok"));
    assert_eq!(wire["messages"][2]["role"], json!("assistant"));
    assert_eq!(
        wire["messages"][2]["content"],
        json!("Let me read the file.")
    );
    assert_eq!(
        wire["messages"][2]["tool_calls"][0]["function"]["arguments"],
        json!("{\"path\":\"README.md\"}")
    );
    assert_eq!(
        wire["tools"][0]["function"]["parameters"]["required"][0],
        json!("path")
    );
    // Empty `tool_choice` is OMITTED from the wire body entirely (the struct
    // encoder drops null optional fields; OpenAI treats an absent tool_choice
    // as the default `auto`). Assert absence on the parsed map plus a literal
    // body check so a regression emitting `"tool_choice":null` or an empty
    // string cannot hide.
    assert!(
        !wire
            .as_object()
            .expect("wire body is a JSON object")
            .contains_key("tool_choice"),
        "empty tool_choice must be omitted from the wire body: {wire}"
    );
    assert!(
        !sent[0].body.contains("tool_choice"),
        "wire body must not mention tool_choice at all: {}",
        sent[0].body
    );
}

/// Loop follow-up messages must convert through the real OpenAI Chat request
/// builder: assistant `function.arguments` is the canonical JSON string, and
/// tool results keep wire role/tool_call_id/content instead of being dropped.
/// The captured follow-up messages are replayed directly through the migrated
/// harness; the agent provider loop itself is out of scope here.
#[test]
fn openai_chat_converts_loop_follow_up_messages_to_standard_wire() {
    let first_arguments = json!({"path": "文档.txt"});
    let second_arguments = json!({"path": "a\"b.md"});
    let first_arguments_json =
        serde_json::to_string(&first_arguments).expect("first arguments json");
    let second_arguments_json =
        serde_json::to_string(&second_arguments).expect("second arguments json");
    let mut request = canonical_request(false);
    request["messages"] = json!([
        {"role": "user", "content": [{"type": "text", "text": "hello"}]},
        {"role": "assistant", "content": [
            {"type": "text", "text": "Let me read."},
            {"type": "tool_call", "tool_call_id": "call-1", "name": "read_file",
             "arguments_json": first_arguments_json},
            {"type": "tool_call", "tool_call_id": "call-2", "name": "read_file",
             "arguments_json": second_arguments_json},
        ]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_call_id": "call-1", "content": "ran read_file",
             "is_error": false},
            {"type": "tool_result", "tool_call_id": "call-2", "content": "ran read_file",
             "is_error": false},
        ]},
    ]);

    let home = openai_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let body: JsonValue = serde_json::from_str(&read_provider_fixture("openai_chat/error.json"))
        .expect("error fixture should be JSON");
    transport.push_json(400, body);
    let runner = harness_runner(&home, Arc::clone(&transport));

    let result = run_harness(
        &runner,
        "openai_chat",
        request,
        openai_profile(),
        "synthetic-openai",
    );
    assert!(result["ok"] == json!(false), "{result}");

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("wire body is JSON");
    let messages = wire["messages"].as_array().expect("wire messages");
    assert_eq!(messages[0]["role"], json!("user"));
    assert_eq!(messages[1]["role"], json!("assistant"));
    assert_eq!(messages[1]["content"], json!("Let me read."));
    assert_eq!(
        messages[1]["tool_calls"][0]["function"]["arguments"],
        json!(first_arguments_json)
    );
    assert!(
        messages[1]["tool_calls"][0]["function"]["arguments"].is_string(),
        "function.arguments must be an exact JSON string: {}",
        messages[1]["tool_calls"][0]["function"]["arguments"]
    );
    assert_eq!(
        messages[1]["tool_calls"][1]["function"]["arguments"],
        json!(second_arguments_json)
    );
    assert_eq!(messages[2]["role"], json!("tool"));
    assert_eq!(messages[2]["tool_call_id"], json!("call-1"));
    assert_eq!(messages[2]["content"], json!("ran read_file"));
    assert_eq!(messages[3]["role"], json!("tool"));
    assert_eq!(messages[3]["tool_call_id"], json!("call-2"));
    assert_eq!(messages[3]["content"], json!("ran read_file"));
    assert_eq!(
        messages.len(),
        4,
        "tool results must not be dropped: {wire}"
    );
}

/// Marker-splice collision guard (P3, user text): the wire splices user
/// content parts and tool schemas through literal markers
/// (`__RSS_USER_PARTS_<i>__`, `__RSS_TOOL_SCHEMA_<i>__`), and
/// `string_replace_literal` replaces every occurrence. Marker-like fragments
/// in ordinary or adversarial text must pass through byte-identical.
#[test]
fn openai_chat_wire_preserves_marker_like_user_text() {
    let home = openai_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let body: JsonValue = serde_json::from_str(&read_provider_fixture("openai_chat/error.json"))
        .expect("error fixture should be JSON");
    transport.push_json(400, body);
    let runner = harness_runner(&home, Arc::clone(&transport));
    let mut request = canonical_request(false);
    request["messages"] = json!([
        {
            "role": "user",
            "content": [{"type": "text", "text": "__RSS_USER_PARTS_"}]
        },
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "prefix __RSS_TOOL_SCHEMA__ suffix"}
            ]
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": "__RSS_USER_PARTS_0__ but not alone"
                },
                {
                    "type": "text",
                    "text": "__RSS_USER_PARTS_1__"
                }
            ]
        }
    ]);

    let result = run_harness(
        &runner,
        "openai_chat",
        request,
        openai_profile(),
        "synthetic-openai",
    );
    assert!(result["ok"] == json!(false), "{result}");

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("wire body is JSON");
    let messages = wire["messages"].as_array().expect("messages array");
    let texts = messages
        .iter()
        .filter(|message| message["role"] == json!("user"))
        .flat_map(|message| {
            message["content"]
                .as_array()
                .expect("user content parts array")
                .iter()
                .map(|part| part["text"].as_str().expect("text part").to_string())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        texts,
        vec![
            "__RSS_USER_PARTS_",
            "prefix __RSS_TOOL_SCHEMA__ suffix",
            "__RSS_USER_PARTS_0__ but not alone",
            "__RSS_USER_PARTS_1__",
        ],
        "marker-like user text must survive the splice byte-identical: {wire}"
    );
}

/// Marker-splice collision guard (P3, tool schemas): a tool schema whose JSON
/// text embeds the marker strings inside longer values must be spliced in
/// byte-identical across multi-tool passes.
#[test]
fn openai_chat_wire_preserves_marker_like_tool_schema() {
    let home = openai_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let body: JsonValue = serde_json::from_str(&read_provider_fixture("openai_chat/error.json"))
        .expect("error fixture should be JSON");
    transport.push_json(400, body);
    let runner = harness_runner(&home, Arc::clone(&transport));
    let mut request = canonical_request(false);
    request["tools"] = json!([
        {
            "name": "read_file",
            "description": "schema __RSS_TOOL_SCHEMA_0__ here",
            "schema_json": "{\"type\":\"object\",\"description\":\"marker __RSS_TOOL_SCHEMA_1__ inside\",\"properties\":{\"path\":{\"type\":\"string\"}}}"
        },
        {
            "name": "search_files",
            "description": "parts __RSS_USER_PARTS_0__ mention",
            "schema_json": "{\"type\":\"object\",\"properties\":{\"pattern\":{\"type\":\"string\"}}}"
        }
    ]);

    let result = run_harness(
        &runner,
        "openai_chat",
        request,
        openai_profile(),
        "synthetic-openai",
    );
    assert!(result["ok"] == json!(false), "{result}");

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1);
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("wire body is JSON");
    let tools = wire["tools"].as_array().expect("tools array");
    assert_eq!(
        tools[0]["function"]["parameters"],
        json!({"type":"object","description":"marker __RSS_TOOL_SCHEMA_1__ inside","properties":{"path":{"type":"string"}}}),
        "tool schema must be spliced in byte-identical: {wire}"
    );
    assert_eq!(
        tools[1]["function"]["parameters"],
        json!({"type":"object","properties":{"pattern":{"type":"string"}}}),
        "second tool schema must survive the multi-pass splice: {wire}"
    );
    assert_eq!(
        tools[0]["function"]["description"],
        json!("schema __RSS_TOOL_SCHEMA_0__ here")
    );
    assert_eq!(
        tools[1]["function"]["description"],
        json!("parts __RSS_USER_PARTS_0__ mention")
    );
}

#[test]
fn openai_chat_malformed_payload_is_typed() {
    let home = openai_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let body: JsonValue =
        serde_json::from_str(&read_provider_fixture("openai_chat/malformed.json"))
            .expect("malformed fixture should be JSON");
    transport.push_json(200, body);
    let runner = harness_runner(&home, Arc::clone(&transport));

    let result = run_harness(
        &runner,
        "openai_chat",
        canonical_request(false),
        openai_profile(),
        "synthetic-openai",
    );

    assert!(result["ok"] == json!(false), "{result}");
    let error = error_of(&result);
    assert_eq!(error["code"], json!("malformed_payload"));
    assert_eq!(error["status"], json!(200));
    assert!(
        error["message"]
            .as_str()
            .expect("message")
            .contains("choices[0].message"),
        "{error:?}"
    );
}

#[test]
fn openai_chat_invalid_json_fails_as_typed_malformed_response() {
    let home = openai_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    transport.push_raw(200, "{not json");
    let runner = harness_runner(&home, Arc::clone(&transport));

    let result = run_harness(
        &runner,
        "openai_chat",
        canonical_request(false),
        openai_profile(),
        "synthetic-openai",
    );

    assert!(result["ok"] == json!(false), "{result}");
    let error = error_of(&result);
    assert_eq!(error["code"], json!("malformed_response"));
    assert!(
        !result.to_string().contains("not json"),
        "raw invalid JSON must not be echoed: {result}"
    );
    assert_eq!(transport.take_sent().len(), 1);
    assert!(!result.to_string().contains("SYNTHETIC_OPENAI_ACCESS"));
}

// ---------------------------------------------------------------------------
// S2: OpenAI Chat Completions, streaming (native auth)
// ---------------------------------------------------------------------------

use opaque_chat_stream::StreamTransport;

fn stream_request() -> JsonValue {
    canonical_request(true)
}

#[test]
fn openai_chat_stream_text_and_usage() {
    let home = openai_home();
    let transport = Arc::new(StreamTransport::new(
        200,
        "text/event-stream",
        sse_events(&read_provider_fixture("openai_chat/stream.sse"))
            .into_iter()
            .map(|event| event.into_bytes())
            .collect(),
        false,
    ));
    let runner = harness_runner(&home, Arc::clone(&transport));

    let result = run_harness(
        &runner,
        "openai_chat",
        stream_request(),
        openai_profile(),
        "synthetic-openai",
    );

    assert!(result["ok"] == json!(true), "{result}");
    let response = response_of(&result);
    assert_eq!(response["text"], json!("The RustScript agent owns policy."));
    assert_eq!(response["stop_reason"], json!("stop"));
    assert_eq!(response["usage"]["input_tokens"], json!(12));
    assert_eq!(response["usage"]["output_tokens"], json!(15));
    assert_eq!(response["usage"]["total_tokens"], json!(27));
    assert_eq!(response["tool_calls"], json!([]));

    let sent = transport.counts.sent.lock().expect("native request");
    assert_eq!(sent.len(), 1, "exactly one admitted stream start");
    assert_eq!(sent[0].method, "POST");
    assert_eq!(
        sent[0].url,
        "https://fixture.example.test/v1/chat/completions"
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
    assert_eq!(wire["stream"], json!(true));
    assert_eq!(wire["stream_options"]["include_usage"], json!(true));
    assert!(!result.to_string().contains("SYNTHETIC_OPENAI_ACCESS"));
}

#[test]
fn openai_chat_stream_tool_call_chunk_aggregation() {
    let home = openai_home();
    let transport = Arc::new(StreamTransport::new(
        200,
        "text/event-stream",
        sse_events(&read_provider_fixture("openai_chat/stream_tools.sse"))
            .into_iter()
            .map(|event| event.into_bytes())
            .collect(),
        false,
    ));
    let runner = harness_runner(&home, Arc::clone(&transport));

    let result = run_harness(
        &runner,
        "openai_chat",
        stream_request(),
        openai_profile(),
        "synthetic-openai",
    );

    assert!(result["ok"] == json!(true), "{result}");
    let response = response_of(&result);
    assert_eq!(response["text"], json!(""));
    assert_eq!(response["stop_reason"], json!("tool_calls"));
    let calls = response["tool_calls"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0]["id"], json!("call_ab12"));
    assert_eq!(calls[0]["name"], json!("read_file"));
    assert_eq!(calls[0]["arguments"], json!({"path": "README.md"}));
    assert_eq!(calls[1]["id"], json!("call_cd34"));
    assert_eq!(calls[1]["name"], json!("search_files"));
    assert_eq!(calls[1]["arguments"], json!({"pattern": "provider"}));
    assert_eq!(response["usage"]["total_tokens"], json!(30));

    let sent = transport.counts.sent.lock().expect("native request");
    assert_eq!(sent.len(), 1);
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("wire body is JSON");
    assert_eq!(wire["stream"], json!(true));
}

#[test]
fn openai_chat_stream_guards_start_nothing() {
    use std::sync::atomic::Ordering;
    let cases: [(&str, &str, Option<JsonValue>, &str); 3] = [
        ("empty-credential", "", None, "missing_credential"),
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
        let home = openai_home();
        let transport = Arc::new(StreamTransport::new(
            200,
            "text/event-stream",
            vec![b"data: [DONE]\n\n".to_vec()],
            false,
        ));
        let runner = harness_runner(&home, Arc::clone(&transport));
        let mut request = stream_request();
        if let Some(options) = private_options {
            request["provider_options"] = options;
        }
        let result = run_harness(
            &runner,
            "openai_chat",
            request,
            openai_profile(),
            credential,
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
fn openai_chat_stream_precancelled_deadline_starts_nothing() {
    use std::sync::atomic::Ordering;
    let home = openai_home();
    let transport = Arc::new(StreamTransport::new(
        200,
        "text/event-stream",
        sse_events(&read_provider_fixture("openai_chat/stream.sse"))
            .into_iter()
            .map(|event| event.into_bytes())
            .collect(),
        false,
    ));
    let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
    cancellation.request(CancellationReason::Requested);
    let runner = harness_runner_with_cancellation(&home, Arc::clone(&transport), cancellation);
    let error = runner
        .run_with_context(provider_opaque_fixture::harness_context(
            "openai_chat",
            stream_request(),
            openai_profile(),
            "synthetic-openai",
        ))
        .expect_err("a pre-cancelled deadline must terminate the run");
    assert!(
        format!("{error:?}").contains("policy_inactive"),
        "a pre-cancelled policy must refuse setup with a typed error, got {error:?}"
    );
    assert_eq!(
        transport.counts.starts.load(Ordering::SeqCst),
        0,
        "pre-cancelled runs must not start a stream"
    );
    assert!(
        transport
            .counts
            .sent
            .lock()
            .expect("recorded native request")
            .is_empty()
    );
}

#[test]
fn openai_chat_stream_deadline_expiry_has_no_partial_success() {
    use rustscript_agent::auth::oauth::ScriptedClock;
    use std::sync::atomic::Ordering;
    let home = openai_home();
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
    let runner = harness_runner_with_clock(&home, Arc::clone(&transport), clock);
    let result = run_harness(
        &runner,
        "openai_chat",
        stream_request(),
        openai_profile(),
        "synthetic-openai",
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

/// A3 review P2 guard: the adapter must fail CLOSED when the server EOFs the
/// SSE body without the terminal `data: [DONE]` event. The failure is the
/// canonical typed provider error, distinct from cancellation and from a
/// legal `[DONE]` stream.
#[test]
fn openai_chat_stream_eof_without_done_fails_closed() {
    use std::sync::atomic::Ordering;
    let home = openai_home();
    let transport = Arc::new(StreamTransport::new(
        200,
        "text/event-stream",
        vec![
            b"data: {\"id\":\"chatcmpl-eof1\",\"object\":\"chat.completion.chunk\",\"created\":1755000009,\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"partial \"},\"finish_reason\":null}]}\n\n".to_vec(),
        ],
        true,
    ));
    let runner = harness_runner(&home, Arc::clone(&transport));

    let result = run_harness(
        &runner,
        "openai_chat",
        stream_request(),
        openai_profile(),
        "synthetic-openai",
    );

    assert!(
        result["ok"] == json!(false),
        "EOF without [DONE] must fail closed, got {result}"
    );
    let error = error_of(&result);
    assert_eq!(error["type"], json!("api_error"));
    assert_eq!(error["code"], json!("stream_eof_without_done"));
    assert_eq!(error["status"], json!(200));
    assert!(
        error["message"]
            .as_str()
            .expect("message")
            .contains("[DONE]"),
        "{error:?}"
    );

    let sent = transport.counts.sent.lock().expect("native request");
    assert_eq!(sent.len(), 1);
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("wire body is JSON");
    assert_eq!(wire["stream"], json!(true));
    assert!(transport.counts.drops.load(Ordering::SeqCst) >= 1);
}

#[test]
fn openai_chat_stream_semantic_invalid_object_is_static_public_failure() {
    use std::sync::atomic::Ordering;
    let home = openai_home();
    let transport = Arc::new(StreamTransport::new(
        200,
        "text/event-stream",
        vec![b"data: {\"id\":\"bounded-but-incomplete\"}\n\n".to_vec()],
        false,
    ));
    let runner = harness_runner(&home, Arc::clone(&transport));
    let result = run_harness(
        &runner,
        "openai_chat",
        stream_request(),
        openai_profile(),
        "synthetic-openai",
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
fn openai_chat_stream_non_json_record_fails_closed_without_echo() {
    use std::sync::atomic::Ordering;
    let home = openai_home();
    let transport = Arc::new(StreamTransport::new(
        200,
        "text/event-stream",
        vec![b"data: not-strict-json\n\n".to_vec()],
        false,
    ));
    let runner = harness_runner(&home, Arc::clone(&transport));
    let result = run_harness(
        &runner,
        "openai_chat",
        stream_request(),
        openai_profile(),
        "synthetic-openai",
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
fn openai_chat_stream_json_array_is_public_failure_and_closes_reader() {
    use std::sync::atomic::Ordering;
    let home = openai_home();
    let transport = Arc::new(StreamTransport::new(
        200,
        "text/event-stream",
        vec![b"data: [1,2]\n\n".to_vec()],
        false,
    ));
    let runner = harness_runner(&home, Arc::clone(&transport));
    let result = run_harness(
        &runner,
        "openai_chat",
        stream_request(),
        openai_profile(),
        "synthetic-openai",
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
fn openai_chat_stream_injected_read_failure_detail_is_not_echoed() {
    use std::sync::atomic::Ordering;
    let home = openai_home();
    let transport = Arc::new(
        StreamTransport::new(200, "text/event-stream", Vec::new(), false)
            .with_read_error("SYNTHETIC_PRIVATE_READ_DETAIL"),
    );
    let runner = harness_runner(&home, Arc::clone(&transport));
    let result = run_harness(
        &runner,
        "openai_chat",
        stream_request(),
        openai_profile(),
        "synthetic-openai",
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
fn openai_chat_stream_http_errors_use_existing_status_classification() {
    use std::sync::atomic::Ordering;
    let cases: [(u16, &str, bool); 2] = [
        (401, "invalid_request_error", false),
        (429, "rate_limit_error", true),
    ];
    for (status, error_type, retryable) in cases {
        let home = openai_home();
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
        let runner = harness_runner(&home, Arc::clone(&transport));
        let result = run_harness(
            &runner,
            "openai_chat",
            stream_request(),
            openai_profile(),
            "synthetic-openai",
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
fn openai_chat_stream_unsupported_mime_fails_closed_without_echo() {
    use std::sync::atomic::Ordering;
    let home = openai_home();
    let transport = Arc::new(StreamTransport::new(
        200,
        "text/plain",
        vec![b"data: {\"choices\":[]}\n\n".to_vec()],
        true,
    ));
    let runner = harness_runner(&home, Arc::clone(&transport));
    let result = run_harness(
        &runner,
        "openai_chat",
        stream_request(),
        openai_profile(),
        "synthetic-openai",
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

// ---------------------------------------------------------------------------
// S3: OpenAI Responses adapter (blocked references)
// ---------------------------------------------------------------------------
//
// `openai_responses.rss` is a typed `not_implemented` stub. The buffered and
// streaming transcripts under `tests/fixtures/providers/openai_responses/`
// document the wire contract; these tests stay ignored until the adapter is
// implemented. The streaming transcript mirrors the real Responses API
// transport: every payload event carries an `event:` line whose value matches
// the `type` field of its `data:` JSON payload, and the stream ends with a
// bare `data: [DONE]`.

#[ignore = "openai_responses adapter is a not_implemented stub (see module doc)"]
#[test]
fn openai_responses_buffered_transcript_is_referenced() {
    let home = openai_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let body: JsonValue =
        serde_json::from_str(&read_provider_fixture("openai_responses/response.json"))
            .expect("fixture json");
    transport.push_json(200, body);
    let runner = harness_runner(&home, Arc::clone(&transport));

    let result = run_harness(
        &runner,
        "openai_responses",
        canonical_request(false),
        openai_profile(),
        "synthetic-openai",
    );

    assert!(result["ok"] == json!(false), "{result}");
    assert_eq!(result["error"]["code"], json!("not_implemented"));
    assert!(transport.take_sent().is_empty());
}

#[ignore = "openai_responses adapter is a not_implemented stub (see module doc)"]
#[test]
fn openai_responses_stream_transcript_matches_real_transport_and_is_referenced() {
    let events = sse_events(&read_provider_fixture("openai_responses/stream.sse"));

    // Real Responses API transport shape: each payload event is an
    // `event: <type>` / `data: {json}` pair with the event name matching the
    // payload's `type` field, and the stream ends with a bare `data: [DONE]`
    // terminator.
    let (done, payload_events) = events
        .split_last()
        .expect("stream fixture must have at least one event");
    for event in payload_events {
        let event_line = event
            .lines()
            .find(|line| line.starts_with("event: "))
            .unwrap_or_else(|| panic!("event must carry an event: line: {event}"));
        let data_line = event
            .lines()
            .find(|line| line.starts_with("data: "))
            .unwrap_or_else(|| panic!("event must carry a data: line: {event}"));
        let event_name = event_line.strip_prefix("event: ").expect("event name");
        let payload: JsonValue =
            serde_json::from_str(data_line.strip_prefix("data: ").expect("data payload"))
                .unwrap_or_else(|error| panic!("data payload must be JSON ({error}): {event}"));
        assert_eq!(
            payload["type"].as_str(),
            Some(event_name),
            "event: line must match the data.type field: {event}"
        );
    }
    assert!(
        done.starts_with("data:") && done.contains("[DONE]"),
        "stream must end with a bare data: [DONE] terminator, got: {done}"
    );

    let home = openai_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let runner = harness_runner(&home, Arc::clone(&transport));

    let result = run_harness(
        &runner,
        "openai_responses",
        canonical_request(true),
        openai_profile(),
        "synthetic-openai",
    );

    assert!(result["ok"] == json!(false), "{result}");
    assert_eq!(result["error"]["code"], json!("not_implemented"));
    assert!(transport.take_sent().is_empty());
}

// ---------------------------------------------------------------------------
// S4: Anthropic Messages adapter (blocked references)
// ---------------------------------------------------------------------------
//
// `anthropic_messages.rss` is a typed `not_implemented` stub. The buffered and
// streaming transcripts under `tests/fixtures/providers/anthropic/` document
// the wire contract; these tests stay ignored until the adapter is
// implemented.

#[ignore = "anthropic_messages adapter is a not_implemented stub (see module doc)"]
#[test]
fn anthropic_messages_buffered_transcript_is_referenced() {
    let home = openai_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let runner = harness_runner(&home, Arc::clone(&transport));

    let result = run_harness(
        &runner,
        "anthropic_messages",
        canonical_request(false),
        json!({"provider": "anthropic"}),
        "synthetic-openai",
    );

    assert!(result["ok"] == json!(false), "{result}");
    assert_eq!(result["error"]["code"], json!("not_implemented"));
    assert!(transport.take_sent().is_empty());
}

#[ignore = "anthropic_messages adapter is a not_implemented stub (see module doc)"]
#[test]
fn anthropic_messages_stream_transcript_is_referenced() {
    let home = openai_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let runner = harness_runner(&home, Arc::clone(&transport));
    let _events = sse_events(&read_provider_fixture("anthropic/stream.sse"));

    let result = run_harness(
        &runner,
        "anthropic_messages",
        canonical_request(true),
        json!({"provider": "anthropic"}),
        "synthetic-openai",
    );

    assert!(result["ok"] == json!(false), "{result}");
    assert_eq!(result["error"]["code"], json!("not_implemented"));
    assert!(transport.take_sent().is_empty());
}

// ---------------------------------------------------------------------------
// Default dispatch aliases through native auth
// ---------------------------------------------------------------------------

#[test]
fn default_dispatch_openrouter_alias_uses_native_auth() {
    let endpoint = &PROFILES[4];
    let home = profile_home(endpoint);
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let body: JsonValue = serde_json::from_str(&read_provider_fixture("openai_chat/response.json"))
        .expect("chat response fixture should be JSON");
    transport.push_json(200, body);
    let runner = dispatch_runner(&home, Arc::clone(&transport));

    let mut request = canonical_request(false);
    request["provider"] = json!("openrouter");
    request["model"] = json!("request-model");
    request["credential_id"] = json!(endpoint.credential);
    let result = run_dispatch(&runner, request);

    assert_eq!(result["ok"], json!(true), "{result}");
    assert_eq!(
        result["response"]["text"],
        json!("The RustScript agent framework keeps provider policy in RSS.")
    );
    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "exactly one native buffered request");
    assert_eq!(
        sent[0].url,
        format!("{}{}", endpoint.origin, endpoint.intent),
        "native trusted authority owns the request URL"
    );
    assert_eq!(
        sent[0].headers.get("authorization").map(String::as_str),
        Some(format!("Bearer {}", endpoint.access).as_str())
    );
    let wire: JsonValue = serde_json::from_str(&sent[0].body).expect("public wire JSON");
    assert_eq!(wire["model"], json!("request-model"));
    assert!(!result.to_string().contains(endpoint.access));
}

#[test]
fn default_dispatch_unknown_provider_stays_unavailable_without_send() {
    let home = openai_home();
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let runner = dispatch_runner(&home, Arc::clone(&transport));

    let mut request = canonical_request(false);
    request["provider"] = json!("anthropic");
    request["credential_id"] = json!("synthetic-openai");
    let result = run_dispatch(&runner, request);

    assert_eq!(result["ok"], json!(false));
    assert_eq!(result["error"]["code"], json!("adapter_unavailable"));
    assert!(transport.take_sent().is_empty());
}

// ---------------------------------------------------------------------------
// C0: harness openai_chat migrates to native auth (RED before migration)
// ---------------------------------------------------------------------------
//
// The production harness must route `openai_chat` through the shared admitted
// profile dispatch into the opaque native-auth Chat entry. The legacy raw
// ambient-HTTP transport is denied by the default agent config, so this
// positive test fails until the migration lands, then proves the canonical
// text/usage contract through actual injected native auth.

#[test]
fn harness_openai_chat_migrates_to_native_auth_with_canonical_text_usage() {
    let home = FixtureHome::for_profile(
        "harness-red",
        "openai",
        "https://fixture.example.test/v1",
        "synthetic-openai",
        "SYNTHETIC_OPENAI_ACCESS",
    );
    let transport = Arc::new(ScriptedHttpsTransport::new());
    let body: JsonValue = serde_json::from_str(&read_provider_fixture("openai_chat/response.json"))
        .expect("chat response fixture should be JSON");
    transport.push_json(200, body);
    let runner = harness_runner(&home, Arc::clone(&transport));
    let profile = json!({
        "provider": "openai",
        "base_url": "https://fixture.example.test/v1",
        "model": "fixture-model",
    });
    let result = run_harness(
        &runner,
        "openai_chat",
        canonical_request(false),
        profile,
        "synthetic-openai",
    );

    assert_eq!(
        result["ok"],
        json!(true),
        "migrated harness must admit the native request: {result}"
    );
    assert_eq!(
        result["response"]["text"],
        json!("The RustScript agent framework keeps provider policy in RSS.")
    );
    assert_eq!(
        result["response"]["reasoning"],
        json!("User asked about the framework; summarize the ownership boundary.")
    );
    assert_eq!(result["response"]["stop_reason"], json!("stop"));
    assert_eq!(result["response"]["usage"]["input_tokens"], json!(12));
    assert_eq!(result["response"]["usage"]["output_tokens"], json!(15));
    assert_eq!(result["response"]["usage"]["total_tokens"], json!(27));
    assert_eq!(result["response"]["tool_calls"], json!([]));

    let sent = transport.take_sent();
    assert_eq!(sent.len(), 1, "exactly one native buffered request");
    assert_eq!(sent[0].method, "POST");
    assert_eq!(
        sent[0].url, "https://fixture.example.test/v1/chat/completions",
        "native trusted authority owns the request URL"
    );
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
    assert_eq!(wire["model"], json!("test-model"));
    assert_eq!(wire["stream"], json!(false));
    assert_eq!(wire["max_tokens"], json!(128));
    assert_eq!(wire["temperature"], json!(0.7));
    assert_eq!(wire["messages"][0]["role"], json!("user"));
    assert_eq!(wire["messages"][0]["content"][0]["text"], json!("hello"));
    assert_eq!(wire["messages"][1]["role"], json!("tool"));
    assert_eq!(wire["messages"][2]["role"], json!("assistant"));
    assert!(!result.to_string().contains("SYNTHETIC_OPENAI_ACCESS"));
}
