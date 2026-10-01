//! Guard the agent-facing HTTP resource boundary, including embedded RSS.

use std::path::{Path, PathBuf};

use rustscript_agent::{AgentConfig, AgentRunner, RunError};
use rustscript_vm::Value;

fn source_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read source directory") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            source_files(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "rss") {
            files.push(path);
        }
    }
}

fn legacy_http_markers(source: &str, rss: bool) -> Vec<&'static str> {
    let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
    let mut markers = Vec::new();
    for old in ["http::client::request({", "http::client::sse({"] {
        if compact.contains(old) {
            markers.push(old);
        }
    }

    let has_http_namespace = compact.contains("http::")
        || compact.contains("usehttp;")
        || compact.contains("usehttp::")
        || compact.contains("usehttpas");
    if has_http_namespace {
        for old in [
            "response[\"status\"]",
            "response[\"body\"]",
            "response[\"headers\"]",
            "stream_result[\"outcome\"]",
            "stream_result[\"status\"]",
            "item[\"kind\"]",
        ] {
            if compact.contains(old) {
                markers.push(old);
            }
        }
        if rss {
            for old in [
                "response.status",
                "response.body",
                "response.headers",
                "stream_result.outcome",
                "stream_result.status",
                "item.kind",
            ] {
                if compact.contains(old) {
                    markers.push(old);
                }
            }
        }
    }
    if compact.contains("http::client::sse(") && compact.contains("{action:\"") {
        markers.push("map SSE callback action");
    }
    markers
}

#[test]
fn typed_oauth_envelope_is_not_mistaken_for_http_response() {
    let source = include_str!("../rss/auth/transport_contract.rss");
    let markers = legacy_http_markers(source, true);
    assert!(
        markers.is_empty(),
        "typed OAuth transport source matched legacy HTTP markers: {markers:?}"
    );
}

#[test]
fn non_http_typed_fields_and_embedded_rust_indexes_are_allowed() {
    let rss = r#"
        use oauth;
        let response = oauth::transport(&request, &usage);
        {status: response.status, body: response.body_without_secret_fields, headers: response.public_headers};
        let stream_result = oauth::stream(&request);
        stream_result.outcome;
        stream_result.status;
        let item = {kind: "oauth"};
        item.kind;
    "#;
    assert!(
        legacy_http_markers(rss, true).is_empty(),
        "non-HTTP RSS fields were reported as legacy HTTP"
    );

    let embedded_rust = r#"
        fn embedded() {
            let response = transport();
            response["status"];
            response["body"];
            response["headers"];
            let stream_result = stream();
            stream_result["outcome"];
            stream_result["status"];
            let item = map![];
            item["kind"];
        }
    "#;
    assert!(
        legacy_http_markers(embedded_rust, false).is_empty(),
        "non-HTTP indexed fields in embedded Rust were reported as legacy HTTP"
    );
}

#[test]
fn indexed_legacy_fields_remain_forbidden_with_http_and_alias_imports() {
    let markers = [
        "response[\"status\"]",
        "response[\"body\"]",
        "response[\"headers\"]",
        "stream_result[\"outcome\"]",
        "stream_result[\"status\"]",
        "item[\"kind\"]",
    ];
    let contexts = [
        (
            "HTTP import and call",
            "use http; fn run() { http::client::request(request); }",
        ),
        (
            "HTTP alias import and call",
            "use http as web; fn run() { web::client::request(request); }",
        ),
    ];
    for marker in markers {
        for (context_name, context) in contexts {
            let source = format!("{context} {marker};");
            assert!(
                legacy_http_markers(&source, true).contains(&marker),
                "{context_name} did not reject {marker}"
            );
            assert!(
                legacy_http_markers(&source, false).contains(&marker),
                "Rust source with {context_name} did not reject {marker}"
            );
        }
    }
    assert!(
        legacy_http_markers("use http; response[\"status\"]", true)
            .contains(&"response[\"status\"]"),
        "an unaliased HTTP import must qualify ambiguous fields"
    );
}

#[test]
fn rss_dot_fields_remain_forbidden_only_with_http_namespace_context() {
    let markers = [
        "response.status",
        "response.body",
        "response.headers",
        "stream_result.outcome",
        "stream_result.status",
        "item.kind",
    ];
    let contexts = [
        (
            "HTTP import and call",
            "use http; fn run() { http::client::request(request); }",
        ),
        (
            "HTTP alias import and call",
            "use http as web; fn run() { web::client::request(request); }",
        ),
    ];
    for marker in markers {
        for (context_name, context) in contexts {
            let source = format!("{context} {marker};");
            assert!(
                legacy_http_markers(&source, true).contains(&marker),
                "{context_name} did not reject RSS marker {marker}"
            );
            assert!(
                !legacy_http_markers(&source, false).contains(&marker),
                "Rust source incorrectly applied RSS marker {marker}"
            );
        }
    }
}

#[test]
fn explicit_map_http_calls_and_sse_callback_action_remain_forbidden() {
    for marker in ["http::client::request({", "http::client::sse({"] {
        assert!(
            legacy_http_markers(marker, false).contains(&marker),
            "explicit legacy call was not reported: {marker}"
        );
    }
    assert!(
        legacy_http_markers(
            r#"use http; http::client::sse(request, |event| { action: "stop" });"#,
            false,
        )
        .contains(&"map SSE callback action"),
        "map-valued SSE callback action was not reported"
    );
    assert!(
        !legacy_http_markers(r#"{ action: "stop" }"#, false).contains(&"map SSE callback action"),
        "map action outside an SSE call was reported"
    );
}

#[test]
fn whitespace_compaction_preserves_every_legacy_marker() {
    let with_whitespace = |text: &str| {
        text.chars()
            .flat_map(|character| [character, ' '])
            .collect::<String>()
    };
    for marker in ["http::client::request({", "http::client::sse({"] {
        let spaced = with_whitespace(marker);
        assert!(
            legacy_http_markers(&spaced, false).contains(&marker),
            "whitespace compaction missed {marker}"
        );
    }
    for marker in [
        "response[\"status\"]",
        "response[\"body\"]",
        "response[\"headers\"]",
        "stream_result[\"outcome\"]",
        "stream_result[\"status\"]",
        "item[\"kind\"]",
    ] {
        let source = format!("use http ; {}", with_whitespace(marker));
        assert!(
            legacy_http_markers(&source, false).contains(&marker),
            "whitespace compaction missed {marker}"
        );
    }
    for marker in [
        "response.status",
        "response.body",
        "response.headers",
        "stream_result.outcome",
        "stream_result.status",
        "item.kind",
    ] {
        let source = format!("use http ; {}", with_whitespace(marker));
        assert!(
            legacy_http_markers(&source, true).contains(&marker),
            "whitespace compaction missed RSS marker {marker}"
        );
    }
    let callback = with_whitespace("http::client::sse(request, {action:\"stop\"})");
    assert!(
        legacy_http_markers(&callback, false).contains(&"map SSE callback action"),
        "whitespace compaction missed the map SSE callback action"
    );
}

#[test]
fn production_and_embedded_http_sources_have_no_map_transport() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    source_files(&root.join("rss"), &mut files);
    source_files(&root.join("examples"), &mut files);
    for name in [
        "runner_tests.rs",
        "gateway_tests.rs",
        "metrics_tests.rs",
        "telegram_tests.rs",
        "provider_tests.rs",
    ] {
        files.push(root.join("tests").join(name));
    }
    let mut violations = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("read source");
        let rss = file.extension().is_some_and(|ext| ext == "rss");
        for marker in legacy_http_markers(&text, rss) {
            violations.push(format!("{}: {marker}", file.display()));
        }
    }
    assert!(
        violations.is_empty(),
        "old HTTP/SSE transport: {violations:#?}"
    );
}

fn assert_rejected(source: &str) -> String {
    match AgentRunner::from_source(source, AgentConfig::default()) {
        Ok(_) => panic!("invalid resource call compiled: {source}"),
        Err(error) => {
            let diagnostic = error.to_string();
            assert!(!diagnostic.is_empty(), "empty compile diagnostic");
            diagnostic
        }
    }
}

fn assert_resource_api_available() {
    AgentRunner::from_source(
        r#"use http;
        pub fn run(input: map) -> int {
            let request = http::request::new("GET", "https://example.com/");
            let response = http::client::request(request);
            http::response::status(&response);
        }"#,
        AgentConfig::default(),
    )
    .expect("core resource API and restricted registry must be available");
}

fn assert_sse_api_available() {
    AgentRunner::from_source(
        r#"use http;
        pub fn run(input: map) -> string {
            let request = http::request::new("GET", "https://example.com/");
            let summary = http::client::sse(request, |event, data, id, retry_ms| true);
            http::sse_summary::outcome(&summary);
        }"#,
        AgentConfig::default(),
    )
    .expect("core SSE callback and summary API must be available");
}

#[test]
fn restricted_registry_admits_only_required_http_and_no_ambient_io() {
    assert_resource_api_available();
    AgentRunner::from_source(
        r#"use http;
        use bytes;
        pub fn run(input: map) -> bool {
            let mut request = http::request::new("GET", "https://example.com/");
            http::request::set_header(&mut request, "accept", "text/plain");
            http::request::set_body_text(&mut request, "hello");
            http::request::set_body_bytes(&mut request, bytes::from_utf8("hello"));
            let response = http::client::request(request);
            let status = http::response::status(&response);
            let url = http::response::url(&response);
            let values = http::response::header_values(&response, "content-type");
            let names = http::response::header_names(&response);
            let body = http::response::body(&response);
            status == 200;
        }"#,
        AgentConfig::default(),
    )
    .expect("all buffered resource APIs must compile");
    AgentRunner::from_source(
        r#"use http;
        fn on_open(status: int, headers: resource<http.headers>, url: string) -> bool {
            let values = http::headers::values(&headers, "content-type");
            let names = http::headers::names(&headers);
            true
        }
        pub fn run(input: map) -> string {
            let request = http::request::new("GET", "https://example.com/");
            let summary = http::client::sse(
                request,
                |event, data, id, retry_ms| true,
                on_open
            );
            let status = http::sse_summary::status(&summary);
            let url = http::sse_summary::url(&summary);
            let headers = http::sse_summary::headers(&summary);
            let values = http::headers::values(&headers, "content-type");
            let names = http::headers::names(&headers);
            let items = http::sse_summary::items(&summary);
            let received = http::sse_summary::bytes_received(&summary);
            let sent = http::sse_summary::bytes_sent(&summary);
            http::sse_summary::outcome(&summary);
        }"#,
        AgentConfig::default(),
    )
    .expect("all SSE resource APIs must compile");
    let ungranted = AgentRunner::from_source(
        r#"use io;
        pub fn run(input: map) -> bool {
            io::exists("/");
        }"#,
        AgentConfig::default(),
    )
    .expect("compile before capability binding");
    let error = ungranted
        .run_with_context(Value::map(vec![]))
        .expect_err("ungranted IO import must fail during VM binding");
    assert!(matches!(error, RunError::Setup(_)), "{error}");
    assert!(
        error
            .to_string()
            .contains("capability profile does not allow builtin 'io_exists'"),
        "{error}"
    );
}

#[test]
fn wrong_resource_key_fails_at_compile_time() {
    assert_resource_api_available();
    assert_rejected(
        r#"use http;
        use sqlite;
        pub fn run(input: map) -> int {
            let db = sqlite::open({ path: ":memory:", mode: "memory" });
            http::response::status(&db);
        }"#,
    );
}

#[test]
fn request_cannot_be_used_after_send() {
    assert_resource_api_available();
    AgentRunner::from_source(
        r#"use http;
        pub fn run(input: map) -> int {
            let mut request = http::request::new("GET", "https://example.com/");
            http::request::set_header(&mut request, "x-test", "late");
            0;
        }"#,
        AgentConfig::default(),
    )
    .expect("the same mutable borrow must compile before the request is sent");
    let diagnostic = assert_rejected(
        r#"use http;
        pub fn run(input: map) -> int {
            let mut request = http::request::new("GET", "https://example.com/");
            let response = http::client::request(request);
            http::request::set_header(&mut request, "x-test", "late");
            0;
        }"#,
    );
    assert!(
        diagnostic.contains("local 'request' was moved earlier"),
        "expected ownership diagnostic, got {diagnostic}"
    );
}

#[test]
fn request_cannot_be_sent_twice() {
    assert_resource_api_available();
    assert_rejected(
        r#"use http;
        pub fn run(input: map) -> int {
            let request = http::request::new("GET", "https://example.com/");
            let first = http::client::request(request);
            let second = http::client::request(request);
            0;
        }"#,
    );
}

#[test]
fn sse_callback_wrong_arity_fails_at_compile_time() {
    assert_sse_api_available();
    assert_rejected(
        r#"use http;
        pub fn run(input: map) -> int {
            let request = http::request::new("GET", "https://example.com/");
            let summary = http::client::sse(request, |data| true);
            0;
        }"#,
    );
}

#[test]
fn sse_callback_non_boolean_result_fails_at_compile_time() {
    assert_sse_api_available();
    assert_rejected(
        r#"use http;
        pub fn run(input: map) -> int {
            let request = http::request::new("GET", "https://example.com/");
            let summary = http::client::sse(request, |event, data, id, retry_ms| { action: "stop" });
            0;
        }"#,
    );
}

#[test]
fn sse_open_callback_non_boolean_result_fails_at_compile_time() {
    assert_sse_api_available();
    assert_rejected(
        r#"use http;
        pub fn run(input: map) -> int {
            let request = http::request::new("GET", "https://example.com/");
            let summary = http::client::sse(
                request,
                |event, data, id, retry_ms| true,
                |status, url, headers| { action: "continue" }
            );
            0;
        }"#,
    );
}
