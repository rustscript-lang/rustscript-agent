use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use rustscript_agent::config_fixture::AuthFixtureHost;
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

fn auth_yaml_expired() -> String {
    auth_yaml().replace("expires_at_ms: 1900000000000", "expires_at_ms: 1")
}

fn auth_yaml_multi() -> String {
    format!(
        "{}\n  secondary:\n    provider: synthetic-provider\n    kind: oauth\n    source: synthetic-test\n    token_type: Bearer\n    access_token: INITIAL_ACCESS_HOST_ONLY\n    refresh_token: INITIAL_REFRESH_HOST_ONLY\n    expires_at_ms: 1900000000000\n    scopes: [scope.synthetic]\n    account_id: acct.synthetic-secondary\n    generation: 0\n    status: active\n",
        auth_yaml().trim_end()
    )
}

fn config_yaml() -> &'static str {
    "version: 1\nmodel:\n  provider: local-agent\n  model: local-agent\n"
}

fn fixture(name: &str) -> (TempRoot, AuthFixtureHost) {
    fixture_from_auth(name, auth_yaml())
}

fn fixture_from_auth(name: &str, auth: impl AsRef<str>) -> (TempRoot, AuthFixtureHost) {
    let root = TempRoot::new(name);
    fs::write(root.0.join("config.yaml"), config_yaml()).expect("config fixture");
    fs::write(root.0.join("auth.yaml"), auth.as_ref()).expect("auth fixture");
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

/// AuthFixtureHost invoke path exposes Complete JSON and the VM Value Debug
/// form. No Event/snapshot collector is wired on this fixture.
fn assert_complete_safe(json: &JsonValue) {
    assert_no_secrets(&json.to_string());
    assert_no_secrets(&format!("{json:?}"));
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
    assert_complete_safe(&saved);
    assert_complete_safe(&loaded);
    assert_complete_safe(&access);
    assert_complete_safe(&refresh);
    let loaded_value = host.run_value("load").expect("RSS load value");
    assert_no_secrets(&format!("{loaded_value:?}"));
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

#[test]
fn rss_corrupt_auth_file_fails_closed_without_secrets() {
    let (root, host) = fixture("corrupt");
    fs::write(root.as_ref().join("auth.yaml"), "{not: [valid").expect("corrupt auth");
    let loaded = host.run_json("load").expect("corrupt load");
    assert_eq!(loaded["ok"], false);
    assert_eq!(loaded["error"]["code"], "corrupt_file");
    assert_complete_safe(&loaded);
    drop(host);
    let recovered = AuthFixtureHost::bind(root.as_ref());
    match recovered {
        Ok(recovered) => {
            let after = recovered.run_json("load").expect("recovered load");
            assert_eq!(after["ok"], false);
            assert_eq!(after["error"]["code"], "corrupt_file");
            assert_complete_safe(&after);
        }
        Err(error) => {
            assert_no_secrets(&error);
            let lower = error.to_lowercase();
            assert!(
                lower.contains("corrupt")
                    || lower.contains("yaml")
                    || lower.contains("parse")
                    || lower.contains("invalid"),
                "rebind must fail closed with a typed parse/corrupt error, got {error}"
            );
        }
    }
}

#[test]
fn rss_same_credential_concurrent_saves_adopt_or_commit() {
    let (_root, host) = fixture("concurrent-same");
    let host = Arc::new(host);
    let left = {
        let host = Arc::clone(&host);
        thread::spawn(move || host.run_json("save"))
    };
    let right = {
        let host = Arc::clone(&host);
        thread::spawn(move || host.run_json("save"))
    };
    let first = left.join().expect("left join").expect("left save");
    let second = right.join().expect("right join").expect("right save");
    assert_eq!(first["ok"], true);
    assert_eq!(second["ok"], true);
    for outcome in [&first["outcome"], &second["outcome"]] {
        assert!(outcome == "committed" || outcome == "adopted");
    }
    assert_complete_safe(&first);
    assert_complete_safe(&second);
    let loaded = host.run_json("load").expect("load after concurrent save");
    assert_eq!(loaded["ok"], true);
    let generation = loaded["metadata"]["generation"]
        .as_u64()
        .expect("generation");
    assert!(generation == 1 || generation == 2);
    assert_complete_safe(&loaded);
}

#[test]
fn rss_multi_credential_save_preserves_the_other_entry() {
    let (_root, host) = fixture_from_auth("multi", auth_yaml_multi());
    let saved = host
        .run_json_for("save", "secondary")
        .expect("secondary save");
    assert_eq!(saved["ok"], true);
    assert_eq!(saved["metadata"]["credential_id"], "secondary");
    assert_eq!(saved["metadata"]["generation"], 1);
    assert_complete_safe(&saved);
    let primary = host.run_json_for("load", "primary").expect("primary load");
    assert_eq!(primary["ok"], true);
    assert_eq!(primary["metadata"]["generation"], 0);
    assert_eq!(primary["metadata"]["credential_id"], "primary");
    let secondary = host
        .run_json_for("load", "secondary")
        .expect("secondary load");
    assert_eq!(secondary["ok"], true);
    assert_eq!(secondary["metadata"]["generation"], 1);
    assert_complete_safe(&primary);
    assert_complete_safe(&secondary);
}

#[test]
fn rss_copied_access_and_refresh_handles_alias_the_issued_capability() {
    let (_root, host) = fixture("handle-copy");
    host.run_json("save").expect("save");
    let access_copy = host.run_json("access_copy").expect("access copy");
    assert_eq!(access_copy["ok"], true);
    assert_eq!(access_copy["handle_class"], "OpaqueAccessHandle");
    let refresh_copy = host.run_json("refresh_copy").expect("refresh copy");
    assert_eq!(refresh_copy["ok"], true);
    assert_eq!(refresh_copy["handle_class"], "OpaqueRefreshHandle");
    assert_complete_safe(&access_copy);
    assert_complete_safe(&refresh_copy);
}

#[test]
fn rss_save_cross_run_is_rejected_by_slot_provenance() {
    let (_root, host) = fixture("cross-run");
    let cross = host.run_json("save_cross_run").expect("cross run");
    assert_eq!(cross["ok"], false);
    assert_eq!(cross["error"]["code"], "secret_slot_provenance");
    assert_complete_safe(&cross);
}

#[test]
fn rss_stale_policy_generation_is_rejected_after_reload() {
    let (_root, mut host) = fixture("stale-policy");
    host.run_json("save").expect("save");
    let old_policy = host.policy_value();
    host.reload_policy().expect("reload");
    let probed = host
        .run_json_with_policy_value("load", old_policy)
        .expect("stale policy");
    assert_eq!(probed["ok"], false);
    assert_eq!(probed["error"]["code"], "policy_handle_invalid");
    assert_complete_safe(&probed);
}

#[test]
fn rss_expired_access_still_issues_a_live_refresh_handle() {
    let (_root, host) = fixture_from_auth("expired-access", auth_yaml_expired());
    let access = host.run_json("access").expect("expired access");
    assert_eq!(access["ok"], false);
    assert_eq!(access["error"]["code"], "handle_expired");
    let refresh = host.run_json("refresh").expect("live refresh");
    assert_eq!(refresh["ok"], true);
    assert_eq!(refresh["handle_class"], "OpaqueRefreshHandle");
    assert_complete_safe(&access);
    assert_complete_safe(&refresh);
}

#[test]
fn rss_duplicate_save_and_handle_replay_fail_closed() {
    let (_root, host) = fixture("duplicates");
    let replay = host.run_json("save_replay").expect("save replay");
    assert_eq!(replay["first"]["ok"], true);
    assert_eq!(replay["second"]["ok"], false);
    assert_eq!(replay["second"]["error"]["code"], "secret_slot_replayed");
    assert_complete_safe(&replay);
    let handle_replay = host.run_json("access_replay").expect("handle replay");
    assert_eq!(handle_replay["first"]["ok"], true);
    assert_eq!(handle_replay["second"]["ok"], false);
    assert_eq!(handle_replay["second"]["error"]["code"], "handle_replayed");
    assert_complete_safe(&handle_replay);
    let refresh_replay = host.run_json("refresh_replay").expect("refresh replay");
    assert_eq!(refresh_replay["first"]["ok"], true);
    assert_eq!(refresh_replay["second"]["ok"], false);
    assert_complete_safe(&refresh_replay);
}

#[test]
fn rss_forged_and_serialized_handles_are_rejected() {
    let (_root, host) = fixture("forged-serialized");
    host.run_json("save").expect("save");
    let forged = host.run_json("access_forged").expect("forged");
    assert_eq!(forged["ok"], false);
    assert_eq!(forged["error"]["code"], "handle_invalid");
    let serialized = host.run_json("access_serialized").expect("serialized");
    assert_eq!(serialized["ok"], true);
    assert_eq!(serialized["reconstructed_ok"], false);
    assert_eq!(serialized["reconstructed_code"], "handle_invalid");
    assert_complete_safe(&forged);
    assert_complete_safe(&serialized);
}

#[test]
fn rss_stale_handles_fail_after_save_rotation() {
    let (_root, host) = fixture("stale-after-save");
    host.run_json("save").expect("initial save");
    let access = host
        .run_json("access_stale_after_save")
        .expect("access after save");
    assert_eq!(access["save_ok"], true);
    assert_eq!(access["consume_ok"], false);
    let access_code = access["consume_code"].as_str().expect("access code");
    assert!(
        access_code == "handle_revoked" || access_code == "generation_conflict",
        "{access:?}"
    );
    assert_complete_safe(&access);
    let refresh = host
        .run_json("refresh_stale_after_save")
        .expect("refresh after save");
    assert_eq!(refresh["save_ok"], true);
    assert_eq!(refresh["consume_ok"], false);
    let refresh_code = refresh["consume_code"].as_str().expect("refresh code");
    assert!(
        refresh_code == "handle_revoked" || refresh_code == "generation_conflict",
        "{refresh:?}"
    );
    assert_complete_safe(&refresh);
}

#[test]
fn rss_refresh_single_flight_rejects_duplicate_until_consumed() {
    let (_root, host) = fixture("refresh-single-flight");
    host.run_json("save").expect("initial save");
    let duplicate = host
        .run_json("refresh_duplicate")
        .expect("duplicate refresh");
    assert_eq!(duplicate["first_ok"], true);
    assert_eq!(duplicate["second_ok"], false);
    assert_eq!(duplicate["second_code"], "handle_replayed");
    assert_eq!(duplicate["consume_ok"], true);
    assert_eq!(duplicate["after_consume_ok"], true);
    assert_complete_safe(&duplicate);
}
