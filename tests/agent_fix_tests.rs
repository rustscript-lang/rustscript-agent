//! A5 review-fix isolated fixtures (one binary so environment-level seams are
//! never shared with other test binaries).
//!
//! Finding F: the built-in storage program load must be FALLIBLE — a
//! deployment without the source tree answers a typed construction error,
//! never an `expect` panic that takes the process down.

use rustscript_agent::{AgentGatewayConfig, AgentGatewayState};

#[test]
fn missing_storage_program_is_a_typed_error_not_a_panic() {
    let root = std::env::temp_dir().join(format!("a5-fix-storage-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("temporary root");
    let db = root.join("state.db");

    // Point the built-in storage program at a path that does not exist (the
    // deployed-without-source-tree scenario). The override is read per
    // construction, so it only affects this test. (Rust 2024 marks env
    // mutation unsafe; this single-threaded test owns the variable.)
    unsafe {
        std::env::set_var(
            "RUSTSCRIPT_STORAGE_PROGRAM",
            root.join("does-not-exist.rss"),
        );
    }
    let outcome = std::panic::catch_unwind(|| {
        AgentGatewayState::with_sqlite_path(AgentGatewayConfig::default(), &db)
    });
    unsafe {
        std::env::remove_var("RUSTSCRIPT_STORAGE_PROGRAM");
    }
    let _ = std::fs::remove_dir_all(&root);

    match outcome {
        Ok(result) => match result {
            Ok(_) => panic!(
                "a missing storage program must be a typed construction error, not a silent success"
            ),
            Err(message) => {
                assert!(
                    message.contains("storage program"),
                    "the typed error must name the failing program: {message}"
                );
            }
        },
        Err(_) => panic!("a missing storage program must never panic"),
    }
}
