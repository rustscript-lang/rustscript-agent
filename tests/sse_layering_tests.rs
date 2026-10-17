use std::path::PathBuf;

#[test]
fn incremental_sse_framing_has_a_transport_owner() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("src/transport/sse.rs");
    assert!(
        path.is_file(),
        "generic SSE framing must live in the transport layer"
    );
    let source = std::fs::read_to_string(path).expect("transport SSE module");
    assert!(source.contains("struct SseFramer"));
    assert!(
        !source.contains("crate::auth"),
        "generic framing must not depend on authentication"
    );
    assert!(
        !source.contains("OAuthError"),
        "framing errors must be transport-local"
    );
}

#[test]
fn authenticated_stream_is_an_auth_adapter_not_an_oauth_parser() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    assert!(!root.join("src/auth/oauth/sanitized_sse.rs").exists());
    let source = std::fs::read_to_string(root.join("src/auth/authenticated_stream.rs"))
        .expect("authenticated stream adapter");
    assert!(source.contains("crate::transport::sse"));
    assert!(!source.contains("fn process_line("));
    assert!(!source.contains("fn process_byte("));
}
