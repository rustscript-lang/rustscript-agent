use std::fs;
use std::os::unix::fs::MetadataExt;
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

const API_KEY_SECRET: &str = "SYNTHETIC_API_KEY_SECRET";

fn api_key_metadata(generation: u64, expires_at_ms: u64) -> CredentialConfig {
    CredentialConfig {
        provider: "synthetic-provider".to_string(),
        kind: "api-key".to_string(),
        source: "operator".to_string(),
        token_type: "Bearer".to_string(),
        expires_at_ms,
        scopes: vec!["scope.synthetic".to_string()],
        account_id: None,
        generation,
        status: "active".to_string(),
        last_refresh_at_ms: None,
        has_refresh_token: false,
    }
}

fn save_api_key(
    store: &AuthStore,
    generation: u64,
    expires_at_ms: u64,
    secret: &str,
) -> Result<SaveOutcome, AuthStoreError> {
    store.save_if_generation(SaveCredentialRequest::new(
        CredentialId::new("primary").expect("credential id"),
        generation,
        1,
        "test-run",
        api_key_metadata(generation, expires_at_ms),
        store
            .fixture_access_slot("primary", generation, 1, "test-run", secret)
            .expect("access slot"),
        RefreshSecretAction::Clear,
    ))
}

#[test]
fn nonexpiring_api_key_saves_reopens_and_issues_one_access() {
    let root = TempRoot::new("api-key-zero");
    let paths = AgentPaths::from_home(root.path.join("home")).expect("paths");
    let store = AuthStore::open(paths.clone()).expect("open");
    let saved = save_api_key(&store, 0, 0, API_KEY_SECRET).expect("api-key zero expiry must save");
    let SaveOutcome::Committed { metadata } = saved else {
        panic!("api-key zero expiry must commit, not adopt an existing record");
    };
    assert_eq!(metadata.kind, "api-key");
    assert_eq!(metadata.expires_at_ms, 0);
    assert_eq!(metadata.generation, 1);
    assert!(!metadata.has_refresh_token);
    assert!(!format!("{metadata:?}").contains(API_KEY_SECRET));

    let reopened = AuthStore::open(paths.clone()).expect("reopen");
    let loaded = reopened.load_metadata("primary").expect("reload metadata");
    assert_eq!(loaded.kind, "api-key");
    assert_eq!(loaded.expires_at_ms, 0);
    assert_eq!(loaded.generation, 1);
    assert!(!loaded.has_refresh_token);
    assert!(!format!("{loaded:?}").contains(API_KEY_SECRET));
    let yaml = fs::read_to_string(&paths.auth).expect("persisted auth");
    assert!(
        yaml.contains("expires_at_ms: 0"),
        "persisted metadata must keep the zero literal"
    );
    assert!(
        yaml.contains("generation: 1"),
        "persisted metadata must keep the committed generation"
    );

    let access = reopened
        .issue_access_handle("primary", 1, 1, "test-run")
        .expect("one access handle for a non-expiring api-key");
    access.validate().expect("issued handle stays live");
    assert_eq!(access.generation(), 1);
    assert_eq!(access.credential_id(), "primary");
    assert!(!format!("{access:?}").contains(API_KEY_SECRET));
}

fn write_private_yaml(paths: &AgentPaths, document: &str) {
    fs::write(&paths.auth, document.as_bytes()).expect("write auth fixture");
    set_private_mode(&paths.auth);
}

#[test]
fn loaded_oauth_zero_expiry_cannot_bypass_metadata_validation() {
    let root = TempRoot::new("oauth-zero-load");
    let paths = AgentPaths::from_home(root.path.join("home")).expect("paths");
    let store = AuthStore::open(paths.clone()).expect("open");
    write_private_yaml(
        &paths,
        &auth_yaml(ACCESS, Some(REFRESH), 3, "active")
            .replace("expires_at_ms: 1900000000000", "expires_at_ms: 0"),
    );
    let loaded = store
        .load_metadata("primary")
        .expect_err("oauth zero expiry must fail metadata validation on load");
    assert!(
        matches!(loaded, AuthStoreError::CorruptFile { .. }),
        "{loaded:?}"
    );
    assert!(loaded.to_string().contains("expires_at_ms"));
    assert_no_secrets(&loaded.to_string());
    let issued = store
        .issue_access_handle("primary", 3, 1, "test-run")
        .expect_err("oauth zero expiry must not issue an access handle");
    assert!(!matches!(issued, AuthStoreError::HandleReplayed { .. }));
    assert_no_secrets(&issued.to_string());
}

fn reject_zero_expiry_save(kind: &str) -> AuthStoreError {
    let root = TempRoot::new("reject-zero");
    let paths = AgentPaths::from_home(root.path.join("home")).expect("paths");
    let store = AuthStore::open(paths).expect("open");
    let mut metadata = api_key_metadata(0, 0);
    metadata.kind = kind.to_string();
    let saved = store.save_if_generation(SaveCredentialRequest::new(
        CredentialId::new("primary").expect("credential id"),
        0,
        1,
        "test-run",
        metadata,
        store
            .fixture_access_slot("primary", 0, 1, "test-run", API_KEY_SECRET)
            .expect("access slot"),
        RefreshSecretAction::Clear,
    ));
    match saved {
        Err(error) => error,
        Ok(_) => panic!("{kind} zero expiry must not save"),
    }
}

#[test]
fn non_api_key_zero_expiry_save_is_rejected() {
    for kind in ["oauth", "unknown", "api_key"] {
        let error = reject_zero_expiry_save(kind);
        assert!(
            matches!(
                &error,
                AuthStoreError::InvalidMetadata { field, .. } if field == "expires_at_ms"
            ),
            "{kind}: {error:?}"
        );
        assert!(error.to_string().contains("must be nonzero"));
        assert_no_secrets(&error.to_string());
    }
}

#[test]
fn loaded_unknown_and_legacy_zero_expiry_cannot_bypass_metadata_validation() {
    for kind in ["unknown", "api_key"] {
        let root = TempRoot::new("unknown-zero-load");
        let paths = AgentPaths::from_home(root.path.join("home")).expect("paths");
        let store = AuthStore::open(paths.clone()).expect("open");
        let document = auth_yaml(ACCESS, Some(REFRESH), 3, "active")
            .replace("kind: oauth", &format!("kind: {kind}"))
            .replace("expires_at_ms: 1900000000000", "expires_at_ms: 0");
        write_private_yaml(&paths, &document);
        let loaded = store
            .load_metadata("primary")
            .expect_err("non-canonical zero expiry must fail on load");
        assert!(
            matches!(loaded, AuthStoreError::CorruptFile { .. }),
            "{kind}: {loaded:?}"
        );
        assert!(loaded.to_string().contains("expires_at_ms"));
        assert_no_secrets(&loaded.to_string());
        let issued = store
            .issue_access_handle("primary", 3, 1, "test-run")
            .expect_err("non-canonical zero expiry must not issue");
        assert_no_secrets(&issued.to_string());
    }
}

#[test]
fn positive_api_key_expiry_still_rejects_and_caps_access() {
    let root = TempRoot::new("api-key-positive");
    let paths = AgentPaths::from_home(root.path.join("home")).expect("paths");
    let store = AuthStore::open(paths).expect("open");
    save_api_key(&store, 0, 1, API_KEY_SECRET).expect("positive expiry saves");
    let expired = store
        .issue_access_handle("primary", 1, 1, "test-run")
        .expect_err("already expired api-key must not issue");
    assert!(matches!(expired, AuthStoreError::HandleExpired { .. }));

    let soon = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
        + 800;
    save_api_key(&store, 1, soon, API_KEY_SECRET).expect("near expiry rotates");
    let handle = store
        .issue_access_handle("primary", 2, 1, "test-run")
        .expect("unexpired positive api-key still issues");
    thread::sleep(Duration::from_millis(1_200));
    let after = handle
        .validate()
        .expect_err("positive api-key expiry must still cap the handle");
    assert!(matches!(after, AuthStoreError::HandleExpired { .. }));
}

#[test]
fn nonexpiring_api_key_keeps_one_shot_run_generation_and_request_bounds() {
    let root = TempRoot::new("api-key-bounds");
    let paths = AgentPaths::from_home(root.path.join("home")).expect("paths");
    let store = AuthStore::open(paths).expect("open");
    save_api_key(&store, 0, 0, API_KEY_SECRET).expect("save");

    let past = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("past");
    let past_issue = store
        .issue_access_handle_until("primary", 1, 1, "test-run", past)
        .expect_err("past request deadline must fail before reveal");
    assert!(matches!(past_issue, AuthStoreError::HandleExpired { .. }));

    let short = Instant::now() + Duration::from_millis(40);
    let short_handle = store
        .issue_access_handle_until("primary", 1, 1, "test-run", short)
        .expect("short request deadline issues");
    thread::sleep(Duration::from_millis(120));
    let short_expired = short_handle
        .validate()
        .expect_err("request deadline must still cap a non-expiring credential");
    assert!(matches!(
        short_expired,
        AuthStoreError::HandleExpired { .. }
    ));

    let access = store
        .issue_access_handle("primary", 1, 1, "test-run")
        .expect("issue");
    let wrong_run = access
        .validate_binding("other", 1, 1, "test-run")
        .expect_err("wrong credential binding must not validate");
    assert!(matches!(wrong_run, AuthStoreError::HandleProvenance { .. }));
    let wrong_run_id = access
        .validate_binding("primary", 1, 1, "other-run")
        .expect_err("wrong run must not validate");
    assert!(matches!(
        wrong_run_id,
        AuthStoreError::HandleProvenance { .. }
    ));
    access
        .validate_binding("primary", 1, 1, "test-run")
        .expect("matching binding still validates");
    let alias = access.clone();
    access.consume().expect("one consume");
    let replayed = alias
        .consume()
        .expect_err("clone cannot consume a used non-expiring handle");
    assert!(matches!(replayed, AuthStoreError::HandleReplayed { .. }));

    let live = store
        .issue_access_handle("primary", 1, 1, "test-run")
        .expect("second issue");
    save_api_key(&store, 1, 0, API_KEY_SECRET).expect("generation rotation");
    let revoked = live
        .consume()
        .expect_err("generation rotation must revoke the previous handle");
    assert!(matches!(revoked, AuthStoreError::HandleRevoked { .. }));
    assert_no_secrets(&revoked.to_string());
}

#[test]
fn nonexpiring_api_key_refresh_still_honors_request_deadline() {
    let root = TempRoot::new("api-key-refresh-bound");
    let paths = AgentPaths::from_home(root.path.join("home")).expect("paths");
    let store = AuthStore::open(paths).expect("open");
    let missing = store
        .issue_refresh_handle("primary", 1, 1, "test-run")
        .expect_err("api-key without a refresh slot must not issue refresh");
    assert!(!matches!(missing, AuthStoreError::HandleExpired { .. }));

    store
        .save_if_generation(SaveCredentialRequest::new(
            CredentialId::new("primary").expect("credential id"),
            0,
            1,
            "test-run",
            api_key_metadata(0, 0),
            store
                .fixture_access_slot("primary", 0, 1, "test-run", API_KEY_SECRET)
                .expect("access slot"),
            RefreshSecretAction::Replace(
                store
                    .fixture_refresh_slot("primary", 0, 1, "test-run", REFRESH)
                    .expect("refresh slot"),
            ),
        ))
        .expect("save api-key with an explicit refresh slot");
    let deadline = Instant::now() + Duration::from_millis(40);
    let refresh = store
        .issue_refresh_handle_until("primary", 1, 1, "test-run", deadline)
        .expect("refresh issue still uses the request deadline");
    thread::sleep(Duration::from_millis(120));
    let expired = refresh
        .validate()
        .expect_err("refresh request deadline must remain in force");
    assert!(matches!(expired, AuthStoreError::HandleExpired { .. }));
}

#[test]
fn expired_canonical_api_key_cannot_issue_the_access_slot_generic_save_requires() {
    let root = TempRoot::new("expired-api-key-no-slot");
    let paths = AgentPaths::from_home(root.path.join("home")).expect("paths");
    let store = AuthStore::open(paths.clone()).expect("open");
    write_private_yaml(
        &paths,
        "version: 1\ncredentials:\n  primary:\n    provider: synthetic-provider\n    kind: api-key\n    source: operator\n    token_type: Bearer\n    access_token: SYNTHETIC_API_KEY_SECRET\n    expires_at_ms: 1\n    scopes: [scope.synthetic]\n    generation: 3\n    status: active\n",
    );
    let issued = store
        .issue_access_handle("primary", 3, 1, "test-run")
        .expect_err("expired positive api-key must not issue an access slot");
    assert!(
        matches!(issued, AuthStoreError::HandleExpired { .. }),
        "{issued:?}"
    );
    assert!(!issued.to_string().contains(API_KEY_SECRET));
    assert_no_secrets(&issued.to_string());
    let loaded = store
        .load_metadata("primary")
        .expect("expired metadata still loads");
    assert_eq!(loaded.kind, "api-key");
    assert_eq!(loaded.expires_at_ms, 1);
    assert_eq!(loaded.generation, 3);
    assert_eq!(loaded.status, "active");
    let yaml = fs::read(&paths.auth).expect("fixture bytes");
    assert!(
        yaml.windows(API_KEY_SECRET.len())
            .any(|window| window == API_KEY_SECRET.as_bytes()),
        "the stored secret must remain in the fixture"
    );
}

fn expired_operator_yaml() -> String {
    "\
version: 1
credentials:
  primary:
    provider: synthetic-provider
    kind: api-key
    source: operator
    token_type: Bearer
    access_token: SYNTHETIC_API_KEY_SECRET
    refresh_token: SYNTHETIC_REFRESH_TOKEN
    expires_at_ms: 1
    scopes: [scope.synthetic]
    generation: 3
    status: active
    last_refresh_at_ms: 42
  secondary:
    provider: synthetic-provider
    kind: oauth
    source: synthetic-test
    token_type: Bearer
    access_token: SYNTHETIC_ACCESS_TOKEN
    refresh_token: SYNTHETIC_REFRESH_TOKEN
    expires_at_ms: 1900000000000
    scopes: [scope.synthetic]
    generation: 7
    status: active
"
    .to_string()
}

fn yaml_credential_field(document: &str, credential: &str, field: &str) -> serde_yaml::Value {
    let parsed: serde_yaml::Value = serde_yaml::from_str(document).expect("auth yaml");
    parsed["credentials"][credential][field].clone()
}

fn assert_secret_field(document: &str, credential: &str, field: &str, expected: &str) {
    let actual = yaml_credential_field(document, credential, field);
    assert!(
        actual.as_str() == Some(expected),
        "{credential}.{field} secret slot changed"
    );
}

#[test]
fn clear_api_key_expiry_converts_expired_positive_record_and_issues_bounded_access() {
    let root = TempRoot::new("clear-expired-api-key");
    let paths = AgentPaths::from_home(root.path.join("home")).expect("paths");
    let store = AuthStore::open(paths.clone()).expect("open");
    write_private_yaml(&paths, &expired_operator_yaml());
    let before = fs::read(&paths.auth).expect("before");
    let cleared = store
        .clear_api_key_expiry_if_generation("primary", 3)
        .expect("operator metadata CAS must clear an expired canonical api-key");
    assert_eq!(cleared.credential_id, "primary");
    assert_eq!(cleared.kind, "api-key");
    assert_eq!(cleared.provider, "synthetic-provider");
    assert_eq!(cleared.source, "operator");
    assert_eq!(cleared.token_type, "Bearer");
    assert_eq!(cleared.expires_at_ms, 0);
    assert_eq!(cleared.scopes, vec!["scope.synthetic".to_string()]);
    assert_eq!(cleared.account_id, None);
    assert_eq!(cleared.generation, 4);
    assert_eq!(cleared.status, "active");
    assert_eq!(cleared.last_refresh_at_ms, Some(42));
    assert!(cleared.has_refresh_token);
    assert!(!format!("{cleared:?}").contains(API_KEY_SECRET));

    let reopened = AuthStore::open(paths.clone()).expect("reopen");
    let loaded = reopened
        .load_metadata("primary")
        .expect("independent readback after the CAS returns");
    assert_eq!(loaded, cleared);
    let secondary = reopened
        .load_metadata("secondary")
        .expect("other record remains");
    assert_eq!(secondary.kind, "oauth");
    assert_eq!(secondary.expires_at_ms, 1_900_000_000_000);
    assert_eq!(secondary.generation, 7);
    assert_eq!(secondary.status, "active");
    assert!(secondary.has_refresh_token);

    let after = fs::read(&paths.auth).expect("after");
    assert_ne!(
        before, after,
        "a real conversion rewrites the document; omitted nulls are not byte identity"
    );
    let after_text = String::from_utf8(after).expect("utf8");
    assert!(
        after_text.contains("account_id: null") || after_text.contains("account_id: ~"),
        "omitted account_id is serialized explicitly and must not be reported as unchanged bytes"
    );
    assert_secret_field(&after_text, "primary", "access_token", API_KEY_SECRET);
    assert_secret_field(&after_text, "primary", "refresh_token", REFRESH);
    assert_secret_field(&after_text, "secondary", "access_token", ACCESS);
    assert_secret_field(&after_text, "secondary", "refresh_token", REFRESH);
    assert_eq!(
        yaml_credential_field(&after_text, "secondary", "expires_at_ms").as_i64(),
        Some(1_900_000_000_000)
    );

    let deadline = Instant::now() + Duration::from_millis(40);
    let access = reopened
        .issue_access_handle_until("primary", 4, 1, "operator-run", deadline)
        .expect("cleared api-key issues a request-bounded handle");
    access
        .validate()
        .expect("handle is live before the request deadline");
    let wrong_run = access
        .validate_binding("primary", 4, 1, "other-run")
        .expect_err("wrong run remains rejected");
    assert!(matches!(wrong_run, AuthStoreError::HandleProvenance { .. }));
    thread::sleep(Duration::from_millis(120));
    let request_expired = access
        .validate()
        .expect_err("request deadline still caps a cleared api-key");
    assert!(matches!(
        request_expired,
        AuthStoreError::HandleExpired { .. }
    ));

    let one_shot = reopened
        .issue_access_handle("primary", 4, 1, "operator-run")
        .expect("second bounded issue");
    one_shot.consume().expect("one consume");
    let replayed = one_shot
        .consume()
        .expect_err("a cleared api-key handle remains one-shot");
    assert!(matches!(replayed, AuthStoreError::HandleReplayed { .. }));
}

struct FileStamp {
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    len: u64,
    bytes: Vec<u8>,
}

fn file_stamp(path: &Path) -> FileStamp {
    let meta = fs::metadata(path).expect("auth fixture metadata");
    FileStamp {
        ino: meta.ino(),
        mtime: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
        len: meta.len(),
        bytes: fs::read(path).expect("auth fixture bytes"),
    }
}

fn assert_file_untouched(path: &Path, before: &FileStamp) {
    let after = file_stamp(path);
    assert_eq!(before.ino, after.ino, "inode changed");
    assert_eq!(before.mtime, after.mtime, "mtime changed");
    assert_eq!(before.mtime_nsec, after.mtime_nsec, "mtime nsec changed");
    assert_eq!(before.len, after.len, "length changed");
    assert!(before.bytes == after.bytes, "document bytes changed");
}

fn canonical_record_yaml(kind: &str, status: &str, expires_at_ms: u64, generation: u64) -> String {
    format!(
        "\
version: 1
credentials:
  primary:
    provider: synthetic-provider
    kind: {kind}
    source: operator
    token_type: Bearer
    access_token: {API_KEY_SECRET}
    expires_at_ms: {expires_at_ms}
    scopes: [scope.synthetic]
    generation: {generation}
    status: {status}
  secondary:
    provider: synthetic-provider
    kind: oauth
    source: synthetic-test
    token_type: Bearer
    access_token: {ACCESS}
    refresh_token: {REFRESH}
    expires_at_ms: 1900000000000
    scopes: [scope.synthetic]
    generation: 7
    status: active
"
    )
}

fn open_operator_fixture(name: &str, document: &str) -> (TempRoot, AgentPaths, AuthStore) {
    let root = TempRoot::new(name);
    let paths = AgentPaths::from_home(root.path.join("home")).expect("paths");
    let store = AuthStore::open(paths.clone()).expect("open");
    write_private_yaml(&paths, document);
    (root, paths, store)
}

#[test]
fn clear_api_key_expiry_rejects_stale_generation_without_write() {
    let (_root, paths, store) = open_operator_fixture(
        "clear-stale-gen",
        &canonical_record_yaml("api-key", "active", 1, 3),
    );
    let before = file_stamp(&paths.auth);
    for expected in [0_u64, 2, 4] {
        let error = store
            .clear_api_key_expiry_if_generation("primary", expected)
            .expect_err("stale generation must conflict");
        assert!(
            matches!(
                error,
                AuthStoreError::GenerationConflict {
                    expected: got_expected,
                    actual: 3,
                    ..
                } if got_expected == expected
            ),
            "stale generation {expected} was not a typed conflict"
        );
        assert!(!error.to_string().contains(API_KEY_SECRET));
        assert_file_untouched(&paths.auth, &before);
    }
    let loaded = store.load_metadata("primary").expect("unchanged record");
    assert_eq!(loaded.generation, 3);
    assert_eq!(loaded.expires_at_ms, 1);
}

#[test]
fn clear_api_key_expiry_rejects_generation_overflow_without_write() {
    let (_root, paths, store) = open_operator_fixture(
        "clear-overflow",
        &canonical_record_yaml("api-key", "active", 1, u64::MAX),
    );
    let loaded = store
        .load_metadata("primary")
        .expect("u64::MAX generation must load from the synthetic fixture");
    assert_eq!(loaded.generation, u64::MAX);
    let before = file_stamp(&paths.auth);
    let error = store
        .clear_api_key_expiry_if_generation("primary", u64::MAX)
        .expect_err("increment past u64::MAX must be rejected before a write");
    assert!(matches!(error, AuthStoreError::GenerationOverflow { .. }));
    assert!(!error.to_string().contains(API_KEY_SECRET));
    assert_file_untouched(&paths.auth, &before);

    let (_noop_root, noop_paths, noop_store) = open_operator_fixture(
        "clear-max-zero-noop",
        &canonical_record_yaml("api-key", "active", 0, u64::MAX),
    );
    let noop_before = file_stamp(&noop_paths.auth);
    let noop = noop_store
        .clear_api_key_expiry_if_generation("primary", u64::MAX)
        .expect("already-zero max generation is a noop, not an overflow");
    assert_eq!(noop.expires_at_ms, 0);
    assert_eq!(noop.generation, u64::MAX);
    assert_file_untouched(&noop_paths.auth, &noop_before);
}

#[test]
fn clear_api_key_expiry_rejects_noncanonical_kind_without_write() {
    for kind in ["oauth", "api_key", "unknown"] {
        let (_root, paths, store) =
            open_operator_fixture("clear-kind", &canonical_record_yaml(kind, "active", 1, 3));
        let before = file_stamp(&paths.auth);
        let error = store
            .clear_api_key_expiry_if_generation("primary", 3)
            .expect_err("noncanonical kind must be rejected");
        assert!(
            matches!(
                error,
                AuthStoreError::InvalidMetadata { ref field, .. } if field == "kind"
            ),
            "kind {kind} was not rejected as metadata"
        );
        assert!(!error.to_string().contains(API_KEY_SECRET));
        assert_file_untouched(&paths.auth, &before);
    }
}

#[test]
fn clear_api_key_expiry_rejects_inactive_and_missing_without_write() {
    let (_root, paths, store) = open_operator_fixture(
        "clear-inactive",
        &canonical_record_yaml("api-key", "inactive", 1, 3),
    );
    let before = file_stamp(&paths.auth);
    let inactive = store
        .clear_api_key_expiry_if_generation("primary", 3)
        .expect_err("inactive record must be rejected");
    assert!(matches!(
        inactive,
        AuthStoreError::InvalidMetadata { ref field, .. } if field == "status"
    ));
    assert!(!inactive.to_string().contains(API_KEY_SECRET));
    assert_file_untouched(&paths.auth, &before);

    let missing = store
        .clear_api_key_expiry_if_generation("absent", 3)
        .expect_err("missing record must be rejected");
    assert!(matches!(missing, AuthStoreError::CredentialNotFound { .. }));
    assert_file_untouched(&paths.auth, &before);
}

#[test]
fn clear_api_key_expiry_zero_record_is_a_noop() {
    let (_root, paths, store) = open_operator_fixture(
        "clear-zero-noop",
        &canonical_record_yaml("api-key", "active", 0, 3),
    );
    let live = store
        .issue_access_handle("primary", 3, 1, "operator-run")
        .expect("already-zero record still issues");
    let before = file_stamp(&paths.auth);
    let cleared = store
        .clear_api_key_expiry_if_generation("primary", 3)
        .expect("matching zero is a noop");
    assert_eq!(cleared.expires_at_ms, 0);
    assert_eq!(cleared.generation, 3);
    assert_eq!(cleared.kind, "api-key");
    assert_eq!(cleared.status, "active");
    assert_file_untouched(&paths.auth, &before);
    live.validate()
        .expect("noop must not revoke a handle from the same generation");
    let reopened = AuthStore::open(paths).expect("reopen");
    let loaded = reopened.load_metadata("primary").expect("readback");
    assert_eq!(loaded, cleared);
}

#[test]
fn clear_api_key_expiry_revokes_previously_issued_live_handle() {
    let expires_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
        + 3_600_000;
    let (_root, paths, store) = open_operator_fixture(
        "clear-revoke-live",
        &canonical_record_yaml("api-key", "active", expires_at_ms, 3),
    );
    let live = store
        .issue_access_handle("primary", 3, 1, "operator-run")
        .expect("still-valid positive record issues");
    live.validate().expect("handle is live before conversion");
    let cleared = store
        .clear_api_key_expiry_if_generation("primary", 3)
        .expect("positive record converts");
    assert_eq!(cleared.expires_at_ms, 0);
    assert_eq!(cleared.generation, 4);
    let revoked = live
        .validate()
        .expect_err("generation conversion must revoke the previous handle");
    assert!(matches!(revoked, AuthStoreError::HandleRevoked { .. }));
    let reopened = AuthStore::open(paths).expect("reopen");
    let loaded = reopened.load_metadata("primary").expect("readback");
    assert_eq!(loaded.generation, 4);
    assert_eq!(loaded.expires_at_ms, 0);
    reopened
        .issue_access_handle("primary", 3, 1, "operator-run")
        .expect_err("old generation must not issue after conversion");
    let replacement = reopened
        .issue_access_handle("primary", 4, 1, "operator-run")
        .expect("new generation issues");
    replacement.consume().expect("one consume");
    let replayed = replacement
        .consume()
        .expect_err("replacement remains one-shot");
    assert!(matches!(replayed, AuthStoreError::HandleReplayed { .. }));
}
