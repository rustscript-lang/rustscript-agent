use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rustscript_agent::config_fixture::AuthFixtureHost;

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
            "rustscript-agent-auth-rss-{name}-{}-{nonce}-{counter}",
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
    "version: 1\ncredentials:\n  primary:\n    provider: synthetic-provider\n    kind: oauth\n    source: synthetic-test\n    token_type: Bearer\n    access_token: INITIAL_ACCESS_HOST_ONLY\n    refresh_token: INITIAL_REFRESH_HOST_ONLY\n    expires_at_ms: 1900000000000\n    scopes: [scope.synthetic]\n    account_id: acct.synthetic\n    generation: 0\n    status: active\n"
}

fn config_yaml() -> &'static str {
    "version: 1\nmodel:\n  provider: local-agent\n  model: local-agent\n"
}

fn fixture(name: &str) -> (TempRoot, AuthFixtureHost) {
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
    let host = AuthFixtureHost::bind(root.0.clone()).expect("auth fixture host");
    (root, host)
}

fn assert_no_secrets(value: &str) {
    assert!(!value.contains("SYNTHETIC"));
    assert!(!value.contains("INITIAL_ACCESS_HOST_ONLY"));
    assert!(!value.contains("INITIAL_REFRESH_HOST_ONLY"));
    assert!(!value.contains("HOST_ONLY"));
}

#[test]
fn rss_round_trip_returns_only_metadata_and_opaque_handles() {
    let (_root, host) = fixture("round-trip");
    let saved = host.run_json("save").expect("RSS save");
    assert_eq!(saved["ok"], true);
    assert_eq!(saved["outcome"], "committed");
    assert_eq!(saved["metadata"]["generation"], 1);
    assert_eq!(saved["metadata"]["has_refresh_token"], true);
    assert_no_secrets(&saved.to_string());

    let loaded = host.run_json("load").expect("RSS metadata load");
    assert_eq!(loaded["ok"], true);
    assert_eq!(loaded["metadata"]["status"], "active");
    let access = host.run_json("access").expect("RSS access handle");
    assert_eq!(access["ok"], true);
    assert_eq!(access["handle_class"], "OpaqueAccessHandle");
    assert_eq!(access["handle"], "<callable>");
    let refresh = host.run_json("refresh").expect("RSS refresh handle");
    assert_eq!(refresh["ok"], true);
    assert_eq!(refresh["handle_class"], "OpaqueRefreshHandle");
    assert_eq!(refresh["handle"], "<callable>");
    assert_no_secrets(&access.to_string());
    assert_no_secrets(&refresh.to_string());
}

#[test]
fn rss_status_and_refresh_decisions_are_preserved_as_labels() {
    let (_root, host) = fixture("decisions");
    host.run_json("save").expect("initial save");
    let reauth = host.run_json("save_reauth").expect("RSS reauth decision");
    assert_eq!(reauth["metadata"]["status"], "reauth_required");
    assert_eq!(reauth["metadata"]["has_refresh_token"], true);
    let cleared = host.run_json("save_clear").expect("RSS clear decision");
    assert_eq!(cleared["metadata"]["status"], "active");
    assert_eq!(cleared["metadata"]["has_refresh_token"], false);
}

#[test]
fn rss_rejects_forged_and_serialized_secret_slots() {
    let (_root, host) = fixture("negative-slots");
    let forged = host.run_json("save_forged").expect("forged result");
    assert_eq!(forged["ok"], false);
    assert_eq!(forged["error"]["code"], "secret_slot_provenance");
    let serialized = host.run_json("save_serialized").expect("serialized result");
    assert_eq!(serialized["ok"], false);
    assert_eq!(serialized["error"]["code"], "secret_slot_provenance");
    let malformed = host.run_json("save_malformed").expect("malformed result");
    assert_eq!(malformed["ok"], false);
    assert_eq!(malformed["error"]["code"], "invalid_metadata");
}

#[test]
fn rss_can_adopt_a_newer_generation_and_replay_is_rejected() {
    let (_root, host) = fixture("generation");
    host.run_json("save").expect("first save");
    let adopted = host.run_json("save_adopt").expect("adopt result");
    assert_eq!(adopted["ok"], true);
    assert_eq!(adopted["outcome"], "adopted");
    let future = host.run_json("save_future").expect("future result");
    assert_eq!(future["ok"], false);
    assert_eq!(future["error"]["code"], "generation_conflict");
    let replay = host.run_json("save_replay").expect("replay result");
    assert_eq!(replay["first"]["ok"], true);
    assert_eq!(replay["second"]["ok"], false);
    assert_eq!(replay["second"]["error"]["code"], "secret_slot_replayed");
}

#[test]
fn rss_fixture_output_is_json_safe_even_when_handles_are_copied() {
    let (_root, host) = fixture("copy");
    let copied = host.run_json("save_copy").expect("copied slot result");
    assert_eq!(copied["ok"], true);
    assert_eq!(copied["metadata"]["generation"], 1);
    assert_no_secrets(&copied.to_string());
}

#[test]
fn rss_delete_removes_the_named_credential() {
    let (_root, host) = fixture("delete");
    host.run_json("save").expect("save");
    let deleted = host.run_json("delete").expect("delete");
    assert_eq!(deleted["ok"], true);
    let missing = host.run_json("load").expect("load after delete");
    assert_eq!(missing["ok"], false);
    assert_eq!(missing["error"]["code"], "credential_not_found");
}

#[test]
fn rss_rejects_forged_serialized_and_replayed_handles() {
    let (_root, host) = fixture("handle-negatives");
    host.run_json("save").expect("save");
    let forged = host.run_json("access_forged").expect("forged handle");
    assert_eq!(forged["ok"], false);
    assert_eq!(forged["error"]["code"], "handle_invalid");
    let serialized = host
        .run_json("access_serialized")
        .expect("serialized handle");
    assert_eq!(serialized["ok"], true);
    assert_eq!(serialized["reconstructed_ok"], false);
    assert_eq!(serialized["reconstructed_code"], "handle_invalid");
    let replay = host.run_json("access_replay").expect("replayed handle");
    assert_eq!(replay["first"]["ok"], true);
    assert_eq!(replay["second"]["ok"], false);
    assert_eq!(replay["second"]["error"]["code"], "handle_replayed");
    let expired = host.run_json("access_expire").expect("expired handle");
    assert_eq!(expired["ok"], false);
    assert_eq!(expired["error"]["code"], "handle_expired");
}

#[test]
fn rss_refresh_local_validation_does_not_consume() {
    let (_root, host) = fixture("refresh-validate");
    host.run_json("save").expect("save");
    let probed = host
        .run_json("refresh_validate")
        .expect("refresh local validation");
    assert_eq!(probed["mismatch_ok"], false);
    assert_eq!(probed["mismatch_code"], "handle_provenance");
    assert_eq!(probed["consume_ok"], true);
    assert_no_secrets(&probed.to_string());
}

#[test]
fn rss_handle_is_invalid_after_owner_restart() {
    let (root, host) = fixture("restart");
    host.run_json("save").expect("save");
    let access = host.run_value("access").expect("live handle");
    let handle = AuthFixtureHost::map_field(&access, "handle").expect("handle field");
    drop(host);
    let restarted = AuthFixtureHost::bind(root.as_ref()).expect("restarted host");
    let probed = restarted
        .run_json_with_injected_handle("injected_check", handle)
        .expect("restart probe");
    assert_eq!(probed["ok"], false);
    assert_eq!(probed["error"]["code"], "handle_invalid");
}

#[test]
fn rss_cross_owner_policy_handle_is_rejected() {
    let (_root, host) = fixture("policy-owner");
    let foreign = fixture("foreign-owner");
    let probed = host
        .run_json_with_policy_value("load", foreign.1.policy_value())
        .expect("cross-owner policy");
    assert_eq!(probed["ok"], false);
    assert_eq!(probed["error"]["code"], "policy_handle_invalid");
}
