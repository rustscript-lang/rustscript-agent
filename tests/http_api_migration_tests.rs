//! Guard the agent-facing HTTP resource boundary, including embedded RSS.

use std::path::{Path, PathBuf};

use rustscript_agent::{AgentConfig, AgentRunner};

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
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        let rss = file.extension().is_some_and(|ext| ext == "rss");
        for old in [
            "http::client::request({",
            "http::client::sse({",
            "response[\"status\"]",
            "response[\"body\"]",
            "response[\"headers\"]",
            "stream_result[\"outcome\"]",
            "stream_result[\"status\"]",
            "item[\"kind\"]",
        ] {
            if compact.contains(old) {
                violations.push(format!("{}: {old}", file.display()));
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
                    violations.push(format!("{}: {old}", file.display()));
                }
            }
        }
        if compact.contains("http::client::sse(") && compact.contains("{action:\"") {
            violations.push(format!("{}: map SSE callback action", file.display()));
        }
    }
    assert!(
        violations.is_empty(),
        "old HTTP/SSE transport: {violations:#?}"
    );
}

fn assert_rejected(source: &str) {
    match AgentRunner::from_source(source, AgentConfig::default()) {
        Ok(_) => panic!("invalid resource call compiled: {source}"),
        Err(error) => assert!(!error.to_string().is_empty(), "empty compile diagnostic"),
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
            let request = http::request::new("GET", "https://example.com/");
            http::request::set_header(&request, "accept", "text/plain");
            http::request::set_body_text(&request, "hello");
            http::request::set_body_bytes(&request, bytes::from_utf8("hello"));
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
        pub fn run(input: map) -> string {
            let request = http::request::new("GET", "https://example.com/");
            let summary = http::client::sse(
                request,
                |event, data, id, retry_ms| true,
                |status, url, headers| {
                    let values = http::headers::values(&headers, "content-type");
                    let names = http::headers::names(&headers);
                    true
                }
            );
            let status = http::sse_summary::status(&summary);
            let url = http::sse_summary::url(&summary);
            let values = http::sse_summary::header_values(&summary, "content-type");
            let names = http::sse_summary::header_names(&summary);
            let items = http::sse_summary::items(&summary);
            let received = http::sse_summary::bytes_received(&summary);
            http::sse_summary::outcome(&summary);
        }"#,
        AgentConfig::default(),
    )
    .expect("all SSE resource APIs must compile");
    assert_rejected(
        r#"use io;
        pub fn run(input: map) -> bool {
            io::exists("/");
        }"#,
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
    assert_rejected(
        r#"use http;
        pub fn run(input: map) -> int {
            let request = http::request::new("GET", "https://example.com/");
            let response = http::client::request(request);
            http::request::set_header(&request, "x-test", "late");
            0;
        }"#,
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
