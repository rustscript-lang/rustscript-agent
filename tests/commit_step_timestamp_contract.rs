//! Static contract for `ServiceEventCommitter::commit_step`.
//!
//! This target does not execute persistence or reopen SQLite. It checks that
//! the method reuses the timestamp already captured by `event_candidate`.

#[test]
fn commit_step_source_reuses_reserved_event_timestamp() {
    let body = commit_step_body(include_str!("../src/service.rs"));
    let marker = "let mut event = event_candidate(";
    let reservation = body
        .find(marker)
        .expect("commit_step reserves one event_candidate");
    assert_eq!(
        body.matches("event_candidate(").count(),
        1,
        "commit_step must reserve exactly one event candidate"
    );
    let after = &body[reservation + marker.len()..];
    assert_eq!(
        after.matches("timestamp()").count(),
        0,
        "commit_step must not call timestamp() after event_candidate; reuse event.timestamp"
    );
    assert_eq!(
        body[..reservation].matches("timestamp()").count(),
        0,
        "commit_step must not sample the clock before event_candidate"
    );
    assert_eq!(
        expression_after(after, "created_at:"),
        "event.timestamp",
        "attached message created_at must use the reserved event timestamp"
    );
    assert_eq!(
        expressions_after(after, "\"now_ms\":"),
        ["event.timestamp", "event.timestamp"],
        "both persist payloads must use the reserved event timestamp"
    );
}

fn commit_step_body(source: &str) -> &str {
    let impl_marker = "impl DurableEventCommitter for ServiceEventCommitter {";
    let impl_at = source
        .find(impl_marker)
        .expect("ServiceEventCommitter impl");
    let rest = &source[impl_at..];
    let method_rel = rest
        .find("\n    fn commit_step(")
        .expect("commit_step method");
    let method = &rest[method_rel + 1..];
    let next = method
        .find("\n    fn ")
        .expect("commit_step is followed by another method");
    &method[..next]
}

fn expression_after<'a>(body: &'a str, marker: &str) -> &'a str {
    let at = body.find(marker).expect("required field marker");
    let rest = body[at + marker.len()..].trim_start();
    let end = rest.find(',').expect("expression comma");
    rest[..end].trim()
}

fn expressions_after<'a>(body: &'a str, marker: &str) -> Vec<&'a str> {
    let mut found = Vec::new();
    let mut rest = body;
    while let Some(at) = rest.find(marker) {
        let after = rest[at + marker.len()..].trim_start();
        let end = after.find(',').expect("expression comma");
        found.push(after[..end].trim());
        rest = &after[end + 1..];
    }
    found
}
