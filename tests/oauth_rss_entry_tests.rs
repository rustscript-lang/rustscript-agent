use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rustscript_agent::config_fixture::OAuthFixtureHost;
use rustscript_agent::runtime::agent_host_catalog;
use serde_json::Value as JsonValue;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(name: &str) -> Self {
        let base = std::env::var_os("TEST_TMPDIR")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after UNIX epoch")
            .as_nanos();
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!(
            "rustscript-agent-oauth-rss-{name}-{}-{nonce}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create RSS fixture root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&path)
                .expect("fixture root metadata")
                .permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&path, permissions).expect("fixture root mode");
        }
        Self(path)
    }
}

impl AsRef<Path> for TempRoot {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn auth_yaml() -> &'static str {
    "version: 1\ncredentials:\n  primary:\n    provider: synthetic-oauth\n    kind: oauth\n    source: synthetic-test\n    token_type: Bearer\n    access_token: INITIAL_ACCESS_HOST_ONLY\n    refresh_token: INITIAL_REFRESH_HOST_ONLY\n    expires_at_ms: 1900000000000\n    scopes: [scope.synthetic]\n    account_id: acct.synthetic\n    generation: 0\n    status: active\n"
}

fn config_yaml() -> &'static str {
    "version: 1\nmodel:\n  provider: synthetic-oauth\n  model: synthetic\nproviders:\n  synthetic-oauth:\n    protocol: oauth\n    base_url: https://api.example.test/v1\n    auth: primary\n    oauth:\n      flow: authorization-code\n      issuer: https://auth.example.test\n      client_id: synthetic-client\n      authorization_path: /authorize\n      token_endpoint: https://auth.example.test/oauth/token\n      device_user_code_path: /oauth/device\n      device_poll_path: /oauth/device/token\n      refresh_skew_seconds: 120\n"
}

fn fixture(name: &str) -> (TempRoot, OAuthFixtureHost) {
    let root = TempRoot::new(name);
    fs::write(root.0.join("config.yaml"), config_yaml()).expect("config fixture");
    fs::write(root.0.join("auth.yaml"), auth_yaml()).expect("auth fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["config.yaml", "auth.yaml"] {
            let path = root.0.join(name);
            let mut permissions = fs::metadata(&path).expect("fixture metadata").permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(path, permissions).expect("fixture mode");
        }
    }
    let host = OAuthFixtureHost::bind(root.0.clone()).expect("oauth fixture host");
    (root, host)
}

fn assert_no_secrets(value: &str) {
    assert!(!value.contains("SYNTHETIC"));
    assert!(!value.contains("INITIAL_ACCESS_HOST_ONLY"));
    assert!(!value.contains("INITIAL_REFRESH_HOST_ONLY"));
    assert!(!value.contains("HOST_ONLY"));
    assert!(!value.contains("code_verifier"));
    assert!(!value.contains("SYNTHETIC_AUTH_CODE"));
}

fn assert_complete_safe(json: &JsonValue) {
    assert_no_secrets(&json.to_string());
    assert_no_secrets(&format!("{json:?}"));
}

#[test]
fn rss_browser_and_manual_login_save_sanitized_tokens() {
    for kind in ["login_browser", "login_manual"] {
        let (_root, host) = fixture(kind);
        let result = host.run_json(kind).expect("login");
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["classified"]["class"], "success");
        assert_eq!(result["saved"]["ok"], true);
        assert_eq!(result["saved"]["metadata"]["generation"], 1);
        assert!(
            result["authorization_url"]
                .as_str()
                .expect("url")
                .starts_with("https://auth.example.test/authorize")
        );
        assert_eq!(result["callback"]["code_handle"], "<callable>");
        assert_eq!(result["transport"]["access_slot"], "<callable>");
        assert_eq!(result["transport"]["refresh_slot"], "<callable>");
        assert!(result["transport"]["body"].get("access_token").is_none());
        assert_complete_safe(&result);
    }
}

#[test]
fn rss_callback_mismatch_timeout_cancel_and_duplicate() {
    let (_root, host) = fixture("callback-cases");
    let mismatch = host.run_json("callback_mismatch").expect("mismatch");
    assert_eq!(mismatch["ok"], false);
    assert_eq!(mismatch["error"]["code"], "state_mismatch");
    assert_complete_safe(&mismatch);

    let (_root_timeout, timeout_host) = fixture("timeout");
    let timeout = timeout_host.run_json("timeout").expect("timeout");
    assert_eq!(timeout["ok"], false);
    assert_eq!(timeout["error"]["code"], "callback_timeout");

    let (_root_cancel, cancel_host) = fixture("cancel");
    let cancel = cancel_host.run_json("cancel").expect("cancel");
    assert_eq!(cancel["ok"], false);
    assert_eq!(cancel["error"]["code"], "callback_cancelled");

    let (_root_dup, dup_host) = fixture("duplicate");
    let duplicate = dup_host.run_json("callback_duplicate").expect("duplicate");
    assert_eq!(duplicate["ok"], true);
    assert_eq!(duplicate["first_ok"], true);
    assert_eq!(duplicate["second_ok"], false);
    assert_eq!(duplicate["second_code"], "handle_replayed");
}

#[test]
fn rss_classifies_401_429_and_5xx() {
    let (_root, host) = fixture("classify");
    let unauthorized = host.run_json("classify_401").expect("401");
    assert_eq!(unauthorized["classified"]["class"], "reauth_required");
    assert_eq!(unauthorized["classified"]["retry"], false);

    let limited = host.run_json("classify_429").expect("429");
    assert_eq!(limited["classified"]["class"], "retryable");
    assert_eq!(limited["classified"]["retry"], true);

    let unavailable = host.run_json("classify_5xx").expect("5xx");
    assert_eq!(unavailable["classified"]["class"], "retryable");
    assert_complete_safe(&unauthorized);
}

#[test]
fn rss_transport_bounds_and_denies_substitution() {
    let (_root, host) = fixture("transport-deny");
    let malformed = host.run_json("transport_malformed").expect("malformed");
    assert_eq!(malformed["ok"], false);
    assert_eq!(malformed["error"]["code"], "malformed_response");

    let oversized = host.run_json("transport_oversized").expect("oversized");
    assert_eq!(oversized["ok"], false);
    assert_eq!(oversized["error"]["code"], "response_too_large");

    let path = host.run_json("transport_denied_path").expect("path");
    assert_eq!(path["ok"], false);
    assert_eq!(path["error"]["code"], "path_denied");

    let header = host.run_json("transport_denied_header").expect("header");
    assert_eq!(header["ok"], false);
    assert_eq!(header["error"]["code"], "header_denied");
}

#[test]
fn rss_refresh_timing_and_backoff_are_rss_owned() {
    let (_root, host) = fixture("timing");
    let due = host.run_json("refresh_due").expect("due");
    assert_eq!(due["due"], true);
    let not_due = host.run_json("refresh_not_due").expect("not due");
    assert_eq!(not_due["due"], false);
    let backoff = host.run_json("retry_backoff").expect("backoff");
    assert_eq!(backoff["wait_ms"], 800);
    let capped = host.run_json("retry_backoff_cap").expect("backoff cap");
    assert_eq!(capped["wait_ms"], 15000);
}

#[test]
fn rss_forged_serialized_and_restart_handles_fail_closed() {
    let (_root, host) = fixture("handles");
    let forged = host.run_json("forged").expect("forged");
    assert_eq!(forged["ok"], false);
    assert_eq!(forged["error"]["code"], "handle_invalid");

    let serialized = host.run_json("serialized").expect("serialized");
    assert_eq!(serialized["ok"], true);
    assert_eq!(serialized["reconstructed_ok"], false);
    assert_eq!(serialized["reconstructed_code"], "handle_invalid");
    assert_complete_safe(&serialized);

    let begun = host.run_value("begin").expect("begin");
    let handle = OAuthFixtureHost::map_field(&begun, "callback_handle").expect("handle");
    drop(host);
    let (_root2, restarted) = fixture("restart");
    let replayed = restarted
        .run_json_with_injected_handle("callback_injected", handle)
        .expect("restart");
    assert_eq!(replayed["ok"], false);
    assert_eq!(replayed["error"]["code"], "handle_invalid");
}

#[test]
fn rss_stale_policy_and_local_refresh_validation() {
    let (_root, host) = fixture("stale");
    let (_other_root, other) = fixture("other-policy");
    let stale = host
        .run_json_with_policy_value("login_browser", other.policy_value())
        .expect("stale policy");
    assert_eq!(stale["ok"], false);
    assert_eq!(stale["error"]["code"], "policy_handle_invalid");

    let validate = host
        .run_json("local_refresh_validate")
        .expect("local validate");
    assert_eq!(validate["ok"], true);
    assert_eq!(validate["denied_ok"], false);
    assert_eq!(validate["denied_code"], "path_denied");
    assert_eq!(validate["validate_ok"], true);

    let access = host
        .run_json("local_access_validate")
        .expect("local access");
    assert_eq!(access["ok"], true);
    assert_eq!(access["denied_ok"], false);
    assert_eq!(access["denied_code"], "path_denied");
    assert_eq!(access["validate_ok"], true);
}

#[test]
fn rss_reserved_form_keys_fail_before_consume() {
    let (_root, host) = fixture("reserved-form");
    let reserved = host
        .run_json("reserved_form_refresh")
        .expect("reserved form");
    assert_eq!(reserved["ok"], true);
    assert_eq!(reserved["denied_ok"], false);
    assert_eq!(reserved["denied_code"], "invalid_intent");
    assert_eq!(reserved["validate_ok"], true);
}

#[test]
fn rss_complete_and_debug_omit_raw_oauth_secrets() {
    let (_root, host) = fixture("secrets");
    let result = host.run_json("secrets_absent").expect("login");
    assert_eq!(result["ok"], true);
    assert_complete_safe(&result);
    let value = host.run_value("secrets_absent").expect("value");
    assert_no_secrets(&format!("{value:?}"));
}

#[test]
fn rss_device_login_pending_slow_down_timeout_cancel_and_denied() {
    let (_root, host) = fixture("device-login");
    let login = host.run_json("device_login").expect("device login");
    assert_eq!(login["ok"], true, "{login}");
    assert_eq!(login["classified"]["class"], "success");
    assert_eq!(login["saved"]["metadata"]["generation"], 1);
    assert_eq!(login["start"]["device_handle"], "<callable>");
    assert!(login["start"]["body"].get("device_code").is_none());
    assert_eq!(login["start"]["body"]["user_code"], "WDJB-MJHT");
    assert_complete_safe(&login);

    let (_root_pending, pending_host) = fixture("device-pending");
    let pending = pending_host
        .run_json("device_pending_success")
        .expect("pending then success");
    assert_eq!(pending["ok"], true, "{pending}");
    assert_eq!(pending["classified"]["class"], "success");
    assert_complete_safe(&pending);

    let (_root_slow, slow_host) = fixture("device-slow");
    let slowed = slow_host.run_json("device_slow_down").expect("slow_down");
    assert_eq!(slowed["ok"], true, "{slowed}");
    assert_eq!(slowed["classified"]["class"], "success");

    let (_root_timeout, timeout_host) = fixture("device-timeout");
    let timeout = timeout_host.run_json("device_timeout").expect("timeout");
    assert_eq!(timeout["ok"], false, "{timeout}");
    assert_eq!(timeout["class"], "timeout");

    let (_root_cancel, cancel_host) = fixture("device-cancel");
    let cancel = cancel_host.run_json("device_cancel").expect("cancel");
    assert_eq!(cancel["ok"], false, "{cancel}");
    assert_eq!(cancel["class"], "cancelled");

    let (_root_denied, denied_host) = fixture("device-denied");
    let denied = denied_host.run_json("device_denied").expect("denied");
    assert_eq!(denied["ok"], false, "{denied}");
    assert_eq!(denied["class"], "denied");
}

#[test]
fn rss_device_and_code_opaque_lifecycle_fail_closed() {
    let (_root, host) = fixture("device-replay");
    let replay = host.run_json("device_replay").expect("device replay");
    assert_eq!(replay["ok"], true, "{replay}");
    assert_eq!(replay["first_ok"], true);
    assert_eq!(replay["second_ok"], false);
    assert_eq!(replay["second_code"], "handle_replayed");
    assert_complete_safe(&replay);

    let forged = host.run_json("device_forged").expect("forged device");
    assert_eq!(forged["ok"], false);
    assert_eq!(forged["error"]["code"], "handle_invalid");

    let serialized = host
        .run_json("device_serialized")
        .expect("serialized device");
    assert_eq!(serialized["ok"], true);
    assert_eq!(serialized["reconstructed_ok"], false);
    assert_eq!(serialized["reconstructed_code"], "handle_invalid");

    let started = host.run_value("device_start").expect("device start");
    let handle = OAuthFixtureHost::map_field(&started, "device_handle").expect("device handle");
    drop(host);
    let (_root2, restarted) = fixture("device-restart");
    let injected = restarted
        .run_json_with_injected_handle("device_injected", handle)
        .expect("restart device");
    assert_eq!(injected["ok"], false);
    assert_eq!(injected["error"]["code"], "handle_invalid");

    let (_root_code, code_host) = fixture("code-replay");
    let code_replay = code_host.run_json("code_replay").expect("code replay");
    assert_eq!(code_replay["ok"], true, "{code_replay}");
    assert_eq!(code_replay["first_ok"], true);
    assert_eq!(code_replay["second_ok"], false);
    assert_eq!(code_replay["second_code"], "handle_replayed");

    let code_serialized = code_host
        .run_json("code_serialized")
        .expect("serialized code");
    assert_eq!(code_serialized["ok"], true);
    assert_eq!(code_serialized["reconstructed_ok"], false);
    assert_eq!(code_serialized["reconstructed_code"], "handle_invalid");
}

#[test]
fn rss_refresh_save_accepts_live_generation() {
    let (_root, host) = fixture("refresh-generation");
    let login = host.run_json("login_browser").expect("login");
    assert_eq!(login["ok"], true, "{login}");
    assert_eq!(login["saved"]["metadata"]["generation"], 1);
    let refresh = host.run_json("refresh_save").expect("refresh save");
    assert_eq!(refresh["ok"], true, "{refresh}");
    assert_eq!(refresh["saved"]["metadata"]["generation"], 2);
    assert_complete_safe(&refresh);
}

#[test]
fn production_catalog_does_not_expose_oauth_bridge() {
    let catalog = agent_host_catalog();
    for function in catalog.functions() {
        assert!(
            !function.name.starts_with("oauth::"),
            "production catalog leaked {}",
            function.name
        );
    }
}
