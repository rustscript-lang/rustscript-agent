use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustscript_agent::auth::store::{AuthMetadata, AuthStore, AuthStoreError};
use rustscript_agent::config_file::AgentPaths;
use rustscript_agent::{
    CredentialConfig, CredentialId, RefreshSecretAction, SaveCredentialRequest, SaveOutcome,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

const ACCESS: &str = "SYNTHETIC_ACCESS_TOKEN";
const REFRESH: &str = "SYNTHETIC_REFRESH_TOKEN";
const ROTATED_ACCESS: &str = "SYNTHETIC_ROTATED_ACCESS";
const ROTATED_REFRESH: &str = "SYNTHETIC_ROTATED_REFRESH";

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new(name: &str) -> Self {
        let base = std::env::var_os("TEST_TMPDIR")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after UNIX epoch")
            .as_nanos();
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!(
            "rustscript-agent-auth-{name}-{}-{nanos}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create auth test root");
        Self { path }
    }
}

impl AsRef<Path> for TempRoot {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn auth_yaml(access: &str, refresh: Option<&str>, generation: u64, status: &str) -> String {
    format!(
        "version: 1\ncredentials:\n  primary:\n    provider: synthetic-provider\n    kind: oauth\n    source: synthetic-test\n    token_type: Bearer\n    access_token: {access}\n    {}    expires_at_ms: 1900000000000\n    scopes: [scope.synthetic]\n    account_id: acct.synthetic\n    generation: {generation}\n    status: {status}\n",
        refresh
            .map(|value| format!("refresh_token: {value}\n"))
            .unwrap_or_default(),
    )
}

fn open_with_yaml(
    name: &str,
    access: &str,
    refresh: Option<&str>,
    generation: u64,
    status: &str,
) -> (TempRoot, AgentPaths, AuthStore) {
    let root = TempRoot::new(name);
    let paths = AgentPaths::from_home(root.path.join("home")).expect("auth path schema");
    let store = AuthStore::open(paths.clone()).expect("store should open without a key");
    fs::write(
        &paths.auth,
        auth_yaml(access, refresh, generation, status).as_bytes(),
    )
    .expect("write fixture auth");
    set_private_mode(&paths.auth);
    (root, paths, store)
}

fn set_private_mode(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path).expect("metadata").permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions).expect("private mode");
    }
}

fn metadata(generation: u64, status: &str) -> CredentialConfig {
    CredentialConfig {
        provider: "synthetic-provider".to_string(),
        kind: "oauth".to_string(),
        source: "synthetic-test".to_string(),
        token_type: "Bearer".to_string(),
        expires_at_ms: 1_900_000_000_000,
        scopes: vec!["scope.synthetic".to_string()],
        account_id: Some("acct.synthetic".to_string()),
        generation,
        status: status.to_string(),
        last_refresh_at_ms: None,
        has_refresh_token: true,
    }
}

fn save_request(
    store: &AuthStore,
    credential_id: &str,
    generation: u64,
    access: &str,
    refresh: RefreshSecretAction,
    status: &str,
) -> SaveCredentialRequest {
    let access_slot = store
        .fixture_access_slot(credential_id, generation, 1, "test-run", access)
        .expect("access slot");
    SaveCredentialRequest::new(
        CredentialId::new(credential_id).expect("credential id"),
        generation,
        1,
        "test-run",
        metadata(generation, status),
        access_slot,
        refresh,
    )
}

fn assert_no_secrets(value: &str) {
    assert!(!value.contains(ACCESS));
    assert!(!value.contains(REFRESH));
    assert!(!value.contains(ROTATED_ACCESS));
    assert!(!value.contains(ROTATED_REFRESH));
}

#[test]
fn load_metadata_is_sanitized_and_plain_yaml_is_readable() {
    let (_root, paths, store) =
        open_with_yaml("metadata", ACCESS, Some(REFRESH), 7, "reauth_required");

    let loaded = store
        .load_metadata("primary")
        .expect("metadata should load");
    assert_eq!(
        loaded,
        AuthMetadata {
            credential_id: "primary".to_string(),
            provider: "synthetic-provider".to_string(),
            kind: "oauth".to_string(),
            source: "synthetic-test".to_string(),
            token_type: "Bearer".to_string(),
            expires_at_ms: 1_900_000_000_000,
            scopes: vec!["scope.synthetic".to_string()],
            account_id: Some("acct.synthetic".to_string()),
            generation: 7,
            status: "reauth_required".to_string(),
            last_refresh_at_ms: None,
            has_refresh_token: true,
        }
    );
    let debug = format!("{loaded:?}");
    assert_no_secrets(&debug);
    let file = String::from_utf8(fs::read(&paths.auth).expect("auth file")).expect("utf8");
    assert!(file.contains("access_token:"));
    assert!(file.contains(ACCESS));
}

#[test]
fn missing_credential_is_typed_without_exposing_secret_material() {
    let (_root, _paths, store) = open_with_yaml("missing", ACCESS, Some(REFRESH), 1, "active");

    let error = store
        .load_metadata("secondary")
        .expect_err("missing credential should be rejected");
    assert!(matches!(
        error,
        AuthStoreError::CredentialNotFound { ref credential_id } if credential_id == "secondary"
    ));
    assert_no_secrets(&error.to_string());
    assert_no_secrets(&format!("{error:?}"));
}

#[cfg(unix)]
#[test]
fn existing_auth_file_with_broad_permissions_is_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let root = TempRoot::new("permissions");
    let home = root.path.join("home");
    fs::create_dir(&home).expect("home");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&home).expect("home metadata").permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&home, permissions).expect("private home mode");
    }
    let paths = AgentPaths::from_home(&home).expect("paths");
    fs::write(&paths.auth, b"version: 1\ncredentials: {}\n").expect("auth");
    let mut permissions = fs::metadata(&paths.auth).expect("metadata").permissions();
    permissions.set_mode(0o644);
    fs::set_permissions(&paths.auth, permissions).expect("broad auth mode");

    let error = AuthStore::open(paths).expect_err("broad auth mode must fail closed");
    assert!(matches!(error, AuthStoreError::InsecurePermissions { .. }));
}

#[cfg(unix)]
#[test]
fn world_writable_home_is_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let root = TempRoot::new("home-mode");
    let home = root.path.join("home");
    fs::create_dir(&home).expect("home");
    let mut permissions = fs::metadata(&home).expect("metadata").permissions();
    permissions.set_mode(0o777);
    fs::set_permissions(&home, permissions).expect("broad home mode");
    let paths = AgentPaths::from_home(&home).expect("paths");
    let error = AuthStore::open(paths).expect_err("broad home mode must fail closed");
    assert!(matches!(error, AuthStoreError::InsecurePermissions { .. }));
}

#[cfg(unix)]
#[test]
fn symlink_auth_file_is_rejected() {
    let root = TempRoot::new("symlink");
    let paths = AgentPaths::from_home(root.path.join("home")).expect("paths");
    let store = AuthStore::open(paths.clone()).expect("open");
    drop(store);
    let target = root.path.join("elsewhere.yaml");
    fs::write(&target, b"version: 1\ncredentials: {}\n").expect("target");
    if paths.auth.exists() {
        fs::remove_file(&paths.auth).expect("remove auth");
    }
    std::os::unix::fs::symlink(&target, &paths.auth).expect("symlink");
    let error = AuthStore::open(paths).expect_err("symlink must fail closed");
    assert!(matches!(error, AuthStoreError::SymlinkRejected { .. }));
}

#[cfg(unix)]
#[test]
fn corrupt_file_is_preserved_and_does_not_expose_secrets_in_errors() {
    let (_root, paths, store) = open_with_yaml("corrupt", ACCESS, Some(REFRESH), 1, "active");
    fs::write(&paths.auth, format!("not: yaml: {ACCESS}\n").as_bytes()).expect("corrupt");
    set_private_mode(&paths.auth);
    let error = store
        .load_metadata("primary")
        .expect_err("corrupt file must fail");
    assert!(matches!(error, AuthStoreError::CorruptFile { .. }));
    assert_no_secrets(&error.to_string());
    assert_no_secrets(&format!("{error:?}"));
    if let AuthStoreError::CorruptFile {
        artifact: Some(artifact),
        ..
    } = error
    {
        assert!(artifact.exists());
    }
}

#[test]
fn save_commits_rotates_and_preserves_other_credentials() {
    let (_root, paths, store) = open_with_yaml("rotate", ACCESS, Some(REFRESH), 0, "active");
    let secondary = auth_yaml(ACCESS, Some(REFRESH), 3, "active").replace("primary:", "secondary:");
    let mut combined = fs::read_to_string(&paths.auth).expect("read");
    combined.push_str(&secondary.replacen("version: 1\ncredentials:\n", "", 1));
    fs::write(&paths.auth, combined).expect("write both");
    set_private_mode(&paths.auth);

    let refresh = RefreshSecretAction::Replace(
        store
            .fixture_refresh_slot("primary", 0, 1, "test-run", ROTATED_REFRESH)
            .expect("refresh slot"),
    );
    let outcome = store
        .save_if_generation(save_request(
            &store,
            "primary",
            0,
            ROTATED_ACCESS,
            refresh,
            "active",
        ))
        .expect("save");
    assert!(!outcome.is_adopted());
    assert_eq!(outcome.metadata().generation, 1);
    assert!(outcome.metadata().has_refresh_token);
    let yaml = fs::read_to_string(&paths.auth).expect("yaml");
    assert!(yaml.contains(ROTATED_ACCESS));
    assert!(yaml.contains(ROTATED_REFRESH));
    assert!(yaml.contains("secondary:"));
    let tmp_left = fs::read_dir(&paths.home)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .contains("auth.yaml.tmp")
        });
    assert!(!tmp_left);
}

#[test]
fn generation_conflict_and_adopt_are_typed() {
    let (_root, _paths, store) = open_with_yaml("cas", ACCESS, Some(REFRESH), 2, "active");
    let future = store
        .save_if_generation(save_request(
            &store,
            "primary",
            3,
            ROTATED_ACCESS,
            RefreshSecretAction::Preserve,
            "active",
        ))
        .expect_err("future generation conflicts");
    assert!(matches!(
        future,
        AuthStoreError::GenerationConflict {
            expected: 3,
            actual: 2,
            ..
        }
    ));

    let adopted = store
        .save_if_generation(save_request(
            &store,
            "primary",
            1,
            ROTATED_ACCESS,
            RefreshSecretAction::Preserve,
            "active",
        ))
        .expect("older generation is adopted");
    assert!(matches!(adopted, SaveOutcome::Adopted { .. }));
    assert_eq!(adopted.metadata().generation, 2);
}

#[test]
fn copied_secret_slots_alias_and_replay_is_rejected() {
    let (_root, _paths, store) = open_with_yaml("replay", ACCESS, Some(REFRESH), 0, "active");
    let access = store
        .fixture_access_slot("primary", 0, 1, "test-run", ROTATED_ACCESS)
        .expect("access");
    let refresh = store
        .fixture_refresh_slot("primary", 0, 1, "test-run", ROTATED_REFRESH)
        .expect("refresh");
    let copied_access = access.clone();
    let copied_refresh = refresh.clone();
    store
        .save_if_generation(SaveCredentialRequest::new(
            CredentialId::new("primary").expect("id"),
            0,
            1,
            "test-run",
            metadata(0, "active"),
            copied_access,
            RefreshSecretAction::Replace(copied_refresh),
        ))
        .expect("first save");
    let replayed = store
        .save_if_generation(SaveCredentialRequest::new(
            CredentialId::new("primary").expect("id"),
            0,
            1,
            "test-run",
            metadata(0, "active"),
            access,
            RefreshSecretAction::Replace(refresh),
        ))
        .expect_err("aliased slots are one-shot");
    assert!(matches!(
        replayed,
        AuthStoreError::SecretSlotReplayed { .. }
    ));
}

#[test]
fn access_and_refresh_handles_are_one_shot_and_redacted() {
    let (_root, _paths, store) = open_with_yaml("handles", ACCESS, Some(REFRESH), 4, "active");
    let access = store
        .issue_access_handle("primary", 4, 1, "test-run")
        .expect("access handle");
    let copied = access.clone();
    access.validate().expect("copy aliases a live handle");
    copied.validate().expect("alias remains live");
    assert_no_secrets(&format!("{access:?}"));
    access.consume().expect("consume once");
    let replayed = copied.consume().expect_err("copy is consumed");
    assert!(matches!(replayed, AuthStoreError::HandleReplayed { .. }));

    let refresh = store
        .issue_refresh_handle("primary", 4, 1, "test-run")
        .expect("refresh handle");
    let mismatched = refresh
        .validate_binding("primary", 99, 1, "test-run")
        .expect_err("local validation mismatch");
    assert!(matches!(
        mismatched,
        AuthStoreError::HandleProvenance { .. }
    ));
    refresh
        .validate()
        .expect("failed local validation must not consume");
    refresh.consume().expect("refresh still sendable");

    let expired = store
        .issue_access_handle("primary", 4, 1, "test-run")
        .expect("expiring handle");
    expired.force_expire();
    assert!(matches!(
        expired.validate().expect_err("expired"),
        AuthStoreError::HandleExpired { .. }
    ));
}

#[test]
fn expired_access_credential_still_issues_a_live_refresh_handle() {
    let root = TempRoot::new("expired-access");
    let paths = AgentPaths::from_home(root.path.join("home")).expect("paths");
    let store = AuthStore::open(paths.clone()).expect("open");
    fs::write(
        &paths.auth,
        auth_yaml(ACCESS, Some(REFRESH), 0, "active")
            .replace("expires_at_ms: 1900000000000", "expires_at_ms: 1"),
    )
    .expect("write expired access fixture");
    set_private_mode(&paths.auth);

    let refresh = store
        .issue_refresh_handle("primary", 0, 1, "test-run")
        .expect("refresh handle must ignore access expiry");
    refresh
        .validate()
        .expect("refresh handle must stay live after access expiry");
    refresh.consume().expect("refresh handle remains sendable");

    let access = store
        .issue_access_handle("primary", 0, 1, "test-run")
        .expect_err("expired access must fail closed");
    assert!(matches!(access, AuthStoreError::HandleExpired { .. }));
}

#[test]
fn expired_refresh_transaction_deadline_fails_closed() {
    let (_root, _paths, store) =
        open_with_yaml("refresh-deadline", ACCESS, Some(REFRESH), 4, "active");
    let deadline = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("clock");
    let expired = store
        .issue_refresh_handle_until("primary", 4, 1, "test-run", deadline)
        .expect_err("expired refresh transaction must fail closed");
    assert!(matches!(expired, AuthStoreError::HandleExpired { .. }));
}

#[test]
fn expired_access_request_deadline_fails_closed() {
    let (_root, _paths, store) =
        open_with_yaml("access-deadline", ACCESS, Some(REFRESH), 4, "active");
    let deadline = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("clock");
    let expired = store
        .issue_access_handle_until("primary", 4, 1, "test-run", deadline)
        .expect_err("expired access request deadline must fail closed");
    assert!(matches!(expired, AuthStoreError::HandleExpired { .. }));
}

#[test]
fn delete_removes_the_named_credential_without_generation_cas() {
    let (_root, _paths, store) = open_with_yaml("delete", ACCESS, Some(REFRESH), 4, "active");
    let deleted = store.delete("primary").expect("delete");
    assert_eq!(deleted.generation, 4);
    assert_no_secrets(&format!("{deleted:?}"));
    let missing = store
        .load_metadata("primary")
        .expect_err("named credential is gone");
    assert!(matches!(
        missing,
        AuthStoreError::CredentialNotFound { ref credential_id } if credential_id == "primary"
    ));
}

#[test]
fn concurrent_writers_preserve_distinct_credentials() {
    let root = TempRoot::new("concurrent");
    let paths = AgentPaths::from_home(root.path.join("home")).expect("paths");
    let store = AuthStore::open(paths).expect("open");
    let workers: Vec<_> = (0..4)
        .map(|index| {
            let store = store.clone();
            thread::spawn(move || {
                let id = format!("worker-{index}");
                let refresh = RefreshSecretAction::Replace(
                    store
                        .fixture_refresh_slot(&id, 0, 1, "test-run", ROTATED_REFRESH)
                        .expect("refresh"),
                );
                store
                    .save_if_generation(save_request(
                        &store,
                        &id,
                        0,
                        ROTATED_ACCESS,
                        refresh,
                        "active",
                    ))
                    .expect("save worker")
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("join");
    }
    for index in 0..4 {
        let metadata = store
            .load_metadata(&format!("worker-{index}"))
            .expect("worker metadata");
        assert_eq!(metadata.generation, 1);
        assert_no_secrets(&format!("{metadata:?}"));
    }
}

fn assert_stale_handle(error: AuthStoreError) {
    assert_no_secrets(&error.to_string());
    assert!(
        matches!(
            error,
            AuthStoreError::GenerationConflict { .. } | AuthStoreError::HandleRevoked { .. }
        ),
        "stale handle must fail closed without a secret, got {error:?}"
    );
}

#[test]
fn save_rotation_revokes_previously_issued_handles() {
    let (_root, _paths, store) = open_with_yaml("revoke-save", ACCESS, Some(REFRESH), 0, "active");
    let access = store
        .issue_access_handle("primary", 0, 1, "test-run")
        .expect("access handle");
    let refresh = store
        .issue_refresh_handle("primary", 0, 1, "test-run")
        .expect("refresh handle");

    store
        .save_if_generation(save_request(
            &store,
            "primary",
            0,
            ROTATED_ACCESS,
            RefreshSecretAction::Preserve,
            "active",
        ))
        .expect("rotate generation");

    assert_stale_handle(access.consume().expect_err("old access after CAS"));
    assert_stale_handle(refresh.consume().expect_err("old refresh after CAS"));
}

#[test]
fn delete_revokes_previously_issued_handles() {
    let (_root, _paths, store) =
        open_with_yaml("revoke-delete", ACCESS, Some(REFRESH), 4, "active");
    let access = store
        .issue_access_handle("primary", 4, 1, "test-run")
        .expect("access handle");
    let refresh = store
        .issue_refresh_handle("primary", 4, 1, "test-run")
        .expect("refresh handle");

    store.delete("primary").expect("delete");

    assert_stale_handle(access.consume().expect_err("access after delete"));
    assert_stale_handle(refresh.consume().expect_err("refresh after delete"));
}

#[test]
fn consume_revalidates_store_generation_as_authority() {
    let (_root, paths, store) = open_with_yaml("gen-authority", ACCESS, Some(REFRESH), 4, "active");
    let access = store
        .issue_access_handle("primary", 4, 1, "test-run")
        .expect("access handle");
    let refresh = store
        .issue_refresh_handle("primary", 4, 1, "test-run")
        .expect("refresh handle");

    fs::write(
        &paths.auth,
        auth_yaml(ROTATED_ACCESS, Some(ROTATED_REFRESH), 5, "active").as_bytes(),
    )
    .expect("rotate file outside save");
    set_private_mode(&paths.auth);

    let access_error = access
        .consume()
        .expect_err("out-of-process generation bump must reject access");
    assert!(
        matches!(
            access_error,
            AuthStoreError::GenerationConflict {
                expected: 4,
                actual: 5,
                ..
            }
        ),
        "{access_error:?}"
    );
    assert_no_secrets(&access_error.to_string());

    let refresh_error = refresh
        .consume()
        .expect_err("out-of-process generation bump must reject refresh");
    assert!(
        matches!(
            refresh_error,
            AuthStoreError::GenerationConflict {
                expected: 4,
                actual: 5,
                ..
            }
        ),
        "{refresh_error:?}"
    );
    assert_no_secrets(&refresh_error.to_string());
}

#[test]
fn duplicate_same_generation_refresh_issuance_is_rejected() {
    let (_root, _paths, store) =
        open_with_yaml("refresh-single", ACCESS, Some(REFRESH), 4, "active");
    let first = store
        .issue_refresh_handle("primary", 4, 1, "test-run")
        .expect("first refresh");
    let duplicate = store
        .issue_refresh_handle("primary", 4, 1, "test-run")
        .expect_err("second refresh must fail closed");
    assert!(
        matches!(duplicate, AuthStoreError::HandleReplayed { .. }),
        "{duplicate:?}"
    );
    first
        .validate()
        .expect("rejected duplicate must not consume the live refresh");
    first.consume().expect("original refresh remains sendable");
}

#[test]
fn different_run_id_cannot_issue_second_live_refresh() {
    let (_root, _paths, store) = open_with_yaml("refresh-run", ACCESS, Some(REFRESH), 4, "active");
    let first = store
        .issue_refresh_handle("primary", 4, 1, "run-a")
        .expect("first refresh");
    let duplicate = store
        .issue_refresh_handle("primary", 4, 1, "run-b")
        .expect_err("different run must not replace live refresh");
    assert!(
        matches!(duplicate, AuthStoreError::HandleReplayed { .. }),
        "{duplicate:?}"
    );
    assert_no_secrets(&duplicate.to_string());
    first
        .validate()
        .expect("rejected run must not consume the live refresh");
    first
        .validate_binding("primary", 4, 1, "run-a")
        .expect("original run remains the sole live flight");
    first.consume().expect("original refresh remains sendable");
}

#[test]
fn different_policy_generation_cannot_replace_live_refresh() {
    let (_root, _paths, store) =
        open_with_yaml("refresh-policy", ACCESS, Some(REFRESH), 4, "active");
    let first = store
        .issue_refresh_handle("primary", 4, 1, "run-a")
        .expect("first refresh");
    let duplicate = store
        .issue_refresh_handle("primary", 4, 2, "run-a")
        .expect_err("different policy generation must not replace live refresh");
    assert!(
        matches!(duplicate, AuthStoreError::HandleReplayed { .. }),
        "{duplicate:?}"
    );
    assert_no_secrets(&duplicate.to_string());
    first
        .validate_binding("primary", 4, 1, "run-a")
        .expect("original policy remains valid for the sole flight");
    let mismatched = first
        .validate_binding("primary", 4, 2, "run-a")
        .expect_err("reloaded policy must not consume the original flight");
    assert!(
        matches!(mismatched, AuthStoreError::HandleProvenance { .. }),
        "{mismatched:?}"
    );
    first
        .consume()
        .expect("original refresh remains sendable under its policy");
}

#[test]
fn consumed_expired_or_revoked_refresh_frees_single_flight() {
    let (_root, _paths, store) = open_with_yaml("refresh-free", ACCESS, Some(REFRESH), 4, "active");

    let first = store
        .issue_refresh_handle("primary", 4, 1, "test-run")
        .expect("first refresh");
    first.consume().expect("consume frees the slot");
    store
        .issue_refresh_handle("primary", 4, 2, "run-after-consume")
        .expect("refresh after consume")
        .force_expire();

    store
        .issue_refresh_handle("primary", 4, 3, "run-after-expire")
        .expect("refresh after expire")
        .force_expire();

    let before_delete = store
        .issue_refresh_handle("primary", 4, 1, "run-before-delete")
        .expect("refresh before delete");
    store.delete("primary").expect("delete revokes in-flight");
    assert_stale_handle(
        before_delete
            .consume()
            .expect_err("deleted credential revokes refresh"),
    );
}

#[test]
fn observed_stale_refresh_releases_single_flight() {
    let (_root, paths, store) =
        open_with_yaml("refresh-stale-slot", ACCESS, Some(REFRESH), 4, "active");
    let first = store
        .issue_refresh_handle("primary", 4, 1, "run-a")
        .expect("first refresh");

    fs::write(
        &paths.auth,
        auth_yaml(ROTATED_ACCESS, Some(ROTATED_REFRESH), 5, "active").as_bytes(),
    )
    .expect("rotate file outside save");
    set_private_mode(&paths.auth);

    let blocked = store
        .issue_refresh_handle("primary", 5, 2, "run-b")
        .expect_err("live stale flight still occupies the slot");
    assert!(
        matches!(blocked, AuthStoreError::HandleReplayed { .. }),
        "{blocked:?}"
    );

    assert_stale_handle(first.consume().expect_err("stale refresh"));
    store
        .issue_refresh_handle("primary", 5, 2, "run-c")
        .expect("slot frees after stale observation")
        .consume()
        .expect("new refresh is sendable");
}

#[test]
fn concurrent_refresh_issuance_across_run_and_policy_is_single_flight() {
    let (_root, _paths, store) = open_with_yaml("refresh-race", ACCESS, Some(REFRESH), 4, "active");
    let workers: Vec<_> = (0..8)
        .map(|index| {
            let store = store.clone();
            thread::spawn(move || {
                store.issue_refresh_handle("primary", 4, 1 + (index % 3), &format!("run-{index}"))
            })
        })
        .collect();
    let mut successes = Vec::new();
    let mut failures = 0usize;
    for worker in workers {
        match worker.join().expect("join refresh worker") {
            Ok(handle) => successes.push(handle),
            Err(error) => {
                assert!(
                    matches!(error, AuthStoreError::HandleReplayed { .. }),
                    "{error:?}"
                );
                assert_no_secrets(&error.to_string());
                failures += 1;
            }
        }
    }
    assert_eq!(successes.len(), 1, "exactly one live refresh");
    assert_eq!(failures, 7);
    successes
        .remove(0)
        .consume()
        .expect("sole live refresh remains consumable");
}

#[test]
fn multiple_access_handles_share_generation_revalidation() {
    let (_root, _paths, store) = open_with_yaml("access-multi", ACCESS, Some(REFRESH), 2, "active");
    let first = store
        .issue_access_handle("primary", 2, 1, "test-run")
        .expect("first access");
    let second = store
        .issue_access_handle("primary", 2, 1, "test-run")
        .expect("second access is allowed");
    first.consume().expect("first access request");
    second
        .validate()
        .expect("sibling access handle stays live until send");
    store
        .save_if_generation(save_request(
            &store,
            "primary",
            2,
            ROTATED_ACCESS,
            RefreshSecretAction::Preserve,
            "active",
        ))
        .expect("rotate");
    assert_stale_handle(second.consume().expect_err("sibling access after CAS"));
}

#[test]
fn expired_secret_slot_save_is_rejected() {
    let (_root, _paths, store) = open_with_yaml("slot-expire", ACCESS, Some(REFRESH), 0, "active");
    let expired = store
        .fixture_access_slot_until(
            "primary",
            0,
            1,
            "test-run",
            ROTATED_ACCESS,
            Instant::now() - Duration::from_secs(1),
        )
        .expect("mint expired slot");
    let error = store
        .save_if_generation(SaveCredentialRequest::new(
            CredentialId::new("primary").expect("id"),
            0,
            1,
            "test-run",
            metadata(0, "active"),
            expired,
            RefreshSecretAction::Preserve,
        ))
        .expect_err("expired slot must fail closed");
    assert!(
        matches!(error, AuthStoreError::SecretSlotExpired { .. }),
        "{error:?}"
    );
    assert_eq!(error.code(), "secret_slot_expired");
    assert_no_secrets(&error.to_string());
    let loaded = store.load_metadata("primary").expect("live credential");
    assert_eq!(loaded.generation, 0);
}

#[test]
fn local_prevalidation_failure_does_not_consume_live_unexpired_slot() {
    let (_root, _paths, store) =
        open_with_yaml("slot-prevalid", ACCESS, Some(REFRESH), 0, "active");
    let live = store
        .fixture_access_slot("primary", 0, 1, "test-run", ROTATED_ACCESS)
        .expect("live slot");
    let mismatched = store
        .save_if_generation(SaveCredentialRequest::new(
            CredentialId::new("primary").expect("id"),
            0,
            2,
            "test-run",
            metadata(0, "active"),
            live.clone(),
            RefreshSecretAction::Preserve,
        ))
        .expect_err("wrong policy generation is local prevalidation");
    assert!(
        matches!(mismatched, AuthStoreError::SecretSlotProvenance { .. }),
        "{mismatched:?}"
    );
    store
        .save_if_generation(SaveCredentialRequest::new(
            CredentialId::new("primary").expect("id"),
            0,
            1,
            "test-run",
            metadata(0, "active"),
            live,
            RefreshSecretAction::Preserve,
        ))
        .expect("live unexpired slot remains usable after local failure");
    let loaded = store.load_metadata("primary").expect("saved");
    assert_eq!(loaded.generation, 1);
}
