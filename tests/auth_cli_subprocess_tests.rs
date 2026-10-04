use std::fs;
#[cfg(all(feature = "default", not(feature = "config-fixture")))]
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const ACCESS_TOKEN: &str = "SYNTHETIC_ACCESS_TOKEN";
const REFRESH_TOKEN: &str = "SYNTHETIC_REFRESH_TOKEN";
const BACKEND_SECRET_MARKER: &str = "acct_synthetic";

struct TestArea {
    root: PathBuf,
    caller: PathBuf,
}

impl TestArea {
    fn new(label: &str) -> Self {
        let root = PathBuf::from(
            std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned Task6 TEMP"),
        );
        let root = root.join(format!("cli-subprocess-{label}-{}", uuid::Uuid::new_v4()));
        let caller = root.join("outside-repository");
        fs::create_dir_all(&caller).expect("create isolated caller directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("private test area");
            fs::set_permissions(&caller, fs::Permissions::from_mode(0o700))
                .expect("private caller directory");
        }
        Self { root, caller }
    }

    fn home(&self, label: &str) -> PathBuf {
        let home = self.root.join(label);
        fs::create_dir_all(&home).expect("create isolated home");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        fs::copy(fixture.join("config.yaml"), home.join("config.yaml"))
            .expect("copy synthetic config fixture");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read synthetic auth fixture")
            .replace("1788440000000", "1900000000000")
            .replace("1788436400000", "1899996400000");
        fs::write(home.join("auth.yaml"), auth).expect("write isolated auth fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("private home");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600))
                    .expect("private fixture file");
            }
        }
        home
    }

    fn binary(&self) -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_rustscript-agent"))
    }

    fn invoke(&self, home: &Path, args: &[&str]) -> Output {
        let binary = self.binary();
        self.invoke_configured(&binary, Some(home), args)
    }

    #[cfg(all(feature = "default", not(feature = "config-fixture")))]
    fn invoke_binary(&self, binary: &Path, home: &Path, args: &[&str]) -> Output {
        self.invoke_configured(binary, Some(home), args)
    }

    fn invoke_without_home(&self, args: &[&str]) -> Output {
        let binary = self.binary();
        self.invoke_configured(&binary, None, args)
    }

    fn invoke_configured(&self, binary: &Path, home: Option<&Path>, args: &[&str]) -> Output {
        let binary = binary.to_path_buf();
        let argv: Vec<String> = std::iter::once(binary.to_string_lossy().into_owned())
            .chain(args.iter().map(|arg| (*arg).to_owned()))
            .collect();
        let group = unsafe { libc::getpgid(0) };
        let mut command = Command::new(&binary);
        command
            .args(args)
            .env("HOME", self.root.join("isolated-default-home"))
            .env_remove("USERPROFILE")
            .current_dir(&self.caller)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(home) = home {
            command.env("RUSTSCRIPT_AGENT_HOME", home);
        } else {
            command.env("RUSTSCRIPT_AGENT_HOME", "");
        }
        let child = command
            .spawn()
            .expect("spawn actual rustscript-agent executable");
        let pid = child.id();
        let output = child
            .wait_with_output()
            .expect("wait for actual CLI process");
        self.record(&argv, pid, &output, group);
        output
    }

    fn record(&self, argv: &[String], pid: u32, output: &Output, process_group: i32) {
        let evidence = PathBuf::from(
            std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned Task6 TEMP"),
        )
        .join("cli-subprocess-evidence");
        fs::create_dir_all(&evidence).expect("create persistent evidence directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&evidence, fs::Permissions::from_mode(0o700))
                .expect("private evidence directory");
        }
        let id = uuid::Uuid::new_v4();
        fs::write(evidence.join(format!("{id}.stdout.raw")), &output.stdout)
            .expect("preserve raw child stdout");
        fs::write(evidence.join(format!("{id}.stderr.raw")), &output.stderr)
            .expect("preserve raw child stderr");
        let status = output
            .status
            .code()
            .map_or_else(|| "signal".to_owned(), |code| code.to_string());
        let metadata = serde_json::json!({
            "argv": argv,
            "cwd": self.caller,
            "inner_exit_code": status,
            "pid": pid,
            "process_group": process_group,
            "stdout_bytes": output.stdout.len(),
            "stderr_bytes": output.stderr.len(),
        });
        let mut file = fs::File::create(evidence.join(format!("{id}.json")))
            .expect("create subprocess metadata");
        file.write_all(
            serde_json::to_string_pretty(&metadata)
                .expect("serialize metadata")
                .as_bytes(),
        )
        .expect("preserve argv, cwd, exit and group");
    }
}

impl Drop for TestArea {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn directory_entries(path: &Path) -> Vec<String> {
    let mut entries: Vec<String> = fs::read_dir(path)
        .expect("read isolated home entries")
        .map(|entry| {
            entry
                .expect("home directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    entries.sort();
    entries
}

#[cfg(all(feature = "default", not(feature = "config-fixture")))]
fn same_file_bytes(left: &Path, right: &Path) -> bool {
    let mut left = match fs::File::open(left) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let mut right = match fs::File::open(right) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let mut left_chunk = [0u8; 64 * 1024];
    let mut right_chunk = [0u8; 64 * 1024];
    loop {
        let left_size = match left.read(&mut left_chunk) {
            Ok(size) => size,
            Err(_) => return false,
        };
        let right_size = match right.read(&mut right_chunk) {
            Ok(size) => size,
            Err(_) => return false,
        };
        if left_size != right_size || left_chunk[..left_size] != right_chunk[..right_size] {
            return false;
        }
        if left_size == 0 {
            return true;
        }
    }
}

fn assert_redacted(output: &Output, home: &Path) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.stdout.len() <= 256 * 1024,
        "stdout exceeded the CLI bound"
    );
    assert!(
        output.stderr.len() <= 256 * 1024,
        "stderr exceeded the CLI bound"
    );
    for marker in [
        ACCESS_TOKEN,
        REFRESH_TOKEN,
        BACKEND_SECRET_MARKER,
        "acct_peer_synthetic",
        "acct_orphan_synthetic",
        "SYNTHETIC_ACCESS",
        "SYNTHETIC_REFRESH",
    ] {
        assert!(!stdout.contains(marker), "stdout leaked a synthetic secret");
        assert!(!stderr.contains(marker), "stderr leaked a synthetic secret");
    }
    for field in [
        "access_token",
        "refresh_token",
        "token_prefix",
        "access_token_prefix",
        "refresh_token_prefix",
        "token_length",
        "access_token_length",
        "refresh_token_length",
        "token_bytes",
    ] {
        assert!(!stdout.contains(field), "stdout exposed token metadata");
        assert!(!stderr.contains(field), "stderr exposed token metadata");
    }
    let home = home.to_string_lossy();
    assert!(
        !stdout.contains(home.as_ref()),
        "stdout leaked the private home path"
    );
    assert!(
        !stderr.contains(home.as_ref()),
        "stderr leaked the private home path"
    );
}

#[test]
fn installed_status_and_config_check_forward_to_the_embedded_guest() {
    let area = TestArea::new("status-config");
    let home = area.home("selected-home");
    let before_entries = directory_entries(&home);
    let before_config = fs::read(home.join("config.yaml")).expect("snapshot config bytes");
    let before_auth = fs::read(home.join("auth.yaml")).expect("snapshot auth bytes");

    let status = area.invoke(&home, &["auth", "status", "openai-codex"]);
    assert_eq!(status.status.code(), Some(0));
    let status_stdout = String::from_utf8(status.stdout.clone()).expect("UTF-8 status output");
    assert!(status_stdout.contains("\"provider\":\"openai-codex\""));
    assert!(status_stdout.contains("\"status\":\"active\""));
    assert!(String::from_utf8_lossy(&status.stderr).is_empty());
    assert_redacted(&status, &home);

    let config = area.invoke(&home, &["config", "check"]);
    assert_eq!(config.status.code(), Some(0));
    let config_stdout = String::from_utf8(config.stdout.clone()).expect("UTF-8 config output");
    assert!(config_stdout.contains("\"kind\":\"selection\""));
    assert!(config_stdout.contains("\"provider\":\"openai-codex\""));
    assert!(String::from_utf8_lossy(&config.stderr).is_empty());
    assert_redacted(&config, &home);

    assert_eq!(directory_entries(&home), before_entries);
    assert_eq!(
        fs::read(home.join("config.yaml")).expect("config remains unchanged"),
        before_config
    );
    assert_eq!(
        fs::read(home.join("auth.yaml")).expect("auth remains unchanged"),
        before_auth
    );
}

#[cfg(all(feature = "default", not(feature = "config-fixture")))]
#[test]
fn installed_binary_matches_cargo_artifact_and_runs_outside_the_repository() {
    let installed = PathBuf::from(
        std::env::var_os("RUSTSCRIPT_AGENT_INSTALLED_BINARY").expect("staging-prefix install path"),
    );
    let built = PathBuf::from(env!("CARGO_BIN_EXE_rustscript-agent"));
    assert!(
        same_file_bytes(&built, &installed),
        "installed artifact differs from Cargo artifact: built={} installed={}",
        built.display(),
        installed.display()
    );

    let area = TestArea::new("installed-artifact");
    assert!(!area.caller.starts_with(env!("CARGO_MANIFEST_DIR")));
    let home = area.home("home");
    let status = area.invoke_binary(&installed, &home, &["auth", "status", "openai-codex"]);
    assert_eq!(status.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&status.stdout).contains("\"status\":\"active\""));
    assert_redacted(&status, &home);
}

#[test]
fn installed_status_and_config_check_use_guest_default_and_reference_policy() {
    let area = TestArea::new("rss-policy");
    let community = area.home("community-default-home");
    let mut config: serde_yaml::Value =
        serde_yaml::from_slice(&fs::read(community.join("config.yaml")).expect("read config"))
            .expect("parse config");
    let mut provider = config["providers"]["openai-codex"].clone();
    provider["auth"] = serde_yaml::Value::Null;
    config["providers"]
        .as_mapping_mut()
        .expect("providers mapping")
        .insert(serde_yaml::Value::String("community".into()), provider);
    config["model"]["provider"] = serde_yaml::Value::String("community".into());
    config["model"]["model"] = serde_yaml::Value::String("community-model-v1".into());
    config["agent"]["source"] = serde_yaml::Value::String("bundled:coding".into());
    fs::write(
        community.join("config.yaml"),
        serde_yaml::to_string(&config).expect("serialize non-vendor selection"),
    )
    .expect("write non-vendor config");
    let community_config_before = fs::read(community.join("config.yaml")).expect("snapshot config");
    let community_auth_before = fs::read(community.join("auth.yaml")).expect("snapshot auth");

    let status = area.invoke(&community, &["auth", "status", "community"]);
    assert_eq!(status.status.code(), Some(0));
    let status_text = String::from_utf8_lossy(&status.stdout);
    assert!(status_text.contains("\"provider\":\"community\""));
    assert!(status_text.contains("\"status\":\"not_configured\""));
    let default = area.invoke(&community, &["config", "check"]);
    assert_eq!(default.status.code(), Some(0));
    let default_text = String::from_utf8_lossy(&default.stdout);
    assert!(default_text.contains("\"provider\":\"community\""));
    assert!(default_text.contains("\"model\":\"community-model-v1\""));
    assert_redacted(&status, &community);
    assert_redacted(&default, &community);
    assert_eq!(
        fs::read(community.join("config.yaml")).expect("non-vendor config unchanged"),
        community_config_before
    );
    assert_eq!(
        fs::read(community.join("auth.yaml")).expect("non-vendor auth unchanged"),
        community_auth_before
    );

    let inactive = area.home("inactive-reference-home");
    let mut config: serde_yaml::Value =
        serde_yaml::from_slice(&fs::read(inactive.join("config.yaml")).expect("read config"))
            .expect("parse config");
    let base_provider = config["providers"]["openai-codex"].clone();
    for (name, id) in [
        ("disabled-provider", "disabled-reference"),
        ("reauth-provider", "reauth-reference"),
        ("missing-provider", "missing-reference"),
    ] {
        let mut provider = base_provider.clone();
        provider["auth"] = serde_yaml::Value::String(id.into());
        config["providers"]
            .as_mapping_mut()
            .expect("providers mapping")
            .insert(serde_yaml::Value::String(name.into()), provider);
    }
    fs::write(
        inactive.join("config.yaml"),
        serde_yaml::to_string(&config).expect("serialize inactive references"),
    )
    .expect("write inactive config");
    let mut auth: serde_yaml::Value =
        serde_yaml::from_slice(&fs::read(inactive.join("auth.yaml")).expect("read auth"))
            .expect("parse auth");
    for (id, state) in [
        ("disabled-reference", "disabled"),
        ("reauth-reference", "reauth_required"),
    ] {
        let mut credential = auth["credentials"]["fixture-codex"].clone();
        credential["status"] = serde_yaml::Value::String(state.into());
        auth["credentials"]
            .as_mapping_mut()
            .expect("credentials mapping")
            .insert(serde_yaml::Value::String(id.into()), credential);
    }
    fs::write(
        inactive.join("auth.yaml"),
        serde_yaml::to_string(&auth).expect("serialize inactive credentials"),
    )
    .expect("write inactive auth");
    let inactive_config_before = fs::read(inactive.join("config.yaml")).expect("snapshot config");
    let inactive_auth_before = fs::read(inactive.join("auth.yaml")).expect("snapshot auth");
    let inactive_entries_before = directory_entries(&inactive);

    let all_status = area.invoke(&inactive, &["auth", "status"]);
    assert_eq!(all_status.status.code(), Some(0));
    let all_text = String::from_utf8_lossy(&all_status.stdout);
    for (provider, state) in [
        ("disabled-provider", "disabled"),
        ("reauth-provider", "reauth_required"),
        ("missing-provider", "missing"),
    ] {
        assert!(all_text.contains(&format!("\"provider\":\"{provider}\"")));
        assert!(all_text.contains(&format!("\"status\":\"{state}\"")));
    }
    let rejected = area.invoke(&inactive, &["config", "check"]);
    assert_eq!(rejected.status.code(), Some(1));
    assert_eq!(rejected.stderr, b"credential_check_failed\n");
    let rejected_text = String::from_utf8_lossy(&rejected.stdout);
    assert!(rejected_text.contains("\"status\":\"disabled\""));
    assert!(rejected_text.contains("\"status\":\"reauth_required\""));
    assert!(rejected_text.contains("\"status\":\"missing\""));
    assert_redacted(&all_status, &inactive);
    assert_redacted(&rejected, &inactive);
    assert_eq!(directory_entries(&inactive), inactive_entries_before);
    assert_eq!(
        fs::read(inactive.join("config.yaml")).expect("invalid config unchanged"),
        inactive_config_before
    );
    assert_eq!(
        fs::read(inactive.join("auth.yaml")).expect("invalid auth unchanged"),
        inactive_auth_before
    );
}

#[test]
fn installed_logout_mutates_only_its_home_and_repeats_as_absent() {
    let area = TestArea::new("logout-isolation");
    let selected = area.home("selected-home");
    let peer_home = area.home("peer-home");
    let mut selected_auth: serde_yaml::Value =
        serde_yaml::from_slice(&fs::read(selected.join("auth.yaml")).expect("read selected auth"))
            .expect("parse selected auth");
    let mut peer_credential = selected_auth["credentials"]["fixture-codex"].clone();
    peer_credential["account_id"] = serde_yaml::Value::String("acct_peer_synthetic".into());
    let mut orphan_credential = selected_auth["credentials"]["fixture-codex"].clone();
    orphan_credential["account_id"] = serde_yaml::Value::String("acct_orphan_synthetic".into());
    let credentials = selected_auth["credentials"]
        .as_mapping_mut()
        .expect("credentials mapping");
    credentials.insert(
        serde_yaml::Value::String("peer-credential".into()),
        peer_credential,
    );
    credentials.insert(
        serde_yaml::Value::String("orphan-credential".into()),
        orphan_credential,
    );
    fs::write(
        selected.join("auth.yaml"),
        serde_yaml::to_string(&selected_auth).expect("serialize peer credential fixture"),
    )
    .expect("write peer credential fixture");

    let peer_before = fs::read(peer_home.join("auth.yaml")).expect("snapshot peer home bytes");
    let selected_config_before = fs::read(selected.join("config.yaml")).expect("snapshot config");
    let selected_before: serde_yaml::Value =
        serde_yaml::from_slice(&fs::read(selected.join("auth.yaml")).expect("snapshot auth"))
            .expect("parse auth snapshot");
    let expected_credentials = {
        let mut credentials = selected_before["credentials"].clone();
        credentials
            .as_mapping_mut()
            .expect("credentials mapping")
            .remove(serde_yaml::Value::String("fixture-codex".into()));
        credentials
    };

    let logout = area.invoke(&selected, &["auth", "logout", "fixture-codex"]);
    assert_eq!(logout.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(logout.stdout.clone()).expect("logout report"),
        "{\"credential_id\":\"fixture-codex\",\"status\":\"deleted\"}\n"
    );
    assert!(logout.stderr.is_empty());
    assert_redacted(&logout, &selected);
    let selected_after: serde_yaml::Value =
        serde_yaml::from_slice(&fs::read(selected.join("auth.yaml")).expect("read changed auth"))
            .expect("parse changed auth");
    assert_eq!(selected_after["credentials"], expected_credentials);
    assert_eq!(
        selected_after["credentials"]["peer-credential"],
        selected_before["credentials"]["peer-credential"]
    );
    assert_eq!(
        fs::read(selected.join("config.yaml")).expect("config unchanged"),
        selected_config_before
    );
    assert_eq!(
        fs::read(peer_home.join("auth.yaml")).expect("peer home unchanged"),
        peer_before
    );

    let repeated = area.invoke(&selected, &["auth", "logout", "fixture-codex"]);
    assert_eq!(repeated.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(repeated.stdout.clone()).expect("repeat logout report"),
        "{\"credential_id\":\"fixture-codex\",\"status\":\"already_absent\"}\n"
    );
    assert!(repeated.stderr.is_empty());
    assert_redacted(&repeated, &selected);

    let orphan_logout = area.invoke(&selected, &["auth", "logout", "orphan-credential"]);
    assert_eq!(orphan_logout.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(orphan_logout.stdout.clone()).expect("orphan logout report"),
        "{\"credential_id\":\"orphan-credential\",\"status\":\"deleted\"}\n"
    );
    let expected_after_orphan = {
        let mut credentials = expected_credentials.clone();
        credentials
            .as_mapping_mut()
            .expect("credentials mapping")
            .remove(serde_yaml::Value::String("orphan-credential".into()));
        credentials
    };
    let after_orphan: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(selected.join("auth.yaml")).expect("read orphan deletion"),
    )
    .expect("parse orphan deletion");
    assert_eq!(after_orphan["credentials"], expected_after_orphan);
    assert_eq!(
        after_orphan["credentials"]["peer-credential"],
        selected_before["credentials"]["peer-credential"]
    );
    let orphan_repeated = area.invoke(&selected, &["auth", "logout", "orphan-credential"]);
    assert_eq!(orphan_repeated.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(orphan_repeated.stdout.clone()).expect("repeat orphan report"),
        "{\"credential_id\":\"orphan-credential\",\"status\":\"already_absent\"}\n"
    );
    assert_redacted(&orphan_logout, &selected);
    assert_redacted(&orphan_repeated, &selected);

    let peer_status = area.invoke(&peer_home, &["auth", "status", "openai-codex"]);
    assert_eq!(peer_status.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&peer_status.stdout).contains("\"status\":\"active\""));
    assert_redacted(&peer_status, &peer_home);
    assert_eq!(
        fs::read(peer_home.join("auth.yaml")).expect("peer home remains byte-identical"),
        peer_before
    );
    assert_eq!(
        fs::read(selected.join("config.yaml")).expect("selected config unchanged"),
        selected_config_before
    );
}

#[test]
fn installed_legacy_and_explicit_run_preserve_last_script_with_bounded_debug_output() {
    let area = TestArea::new("run-compat");
    let home = area.home("home");
    let first = area.root.join("first.rss");
    let last = area.root.join("last.rss");
    fs::write(
        &first,
        "pub fn run(input: string?) -> string { \"first-result\"; }",
    )
    .expect("write first RSS script");
    fs::write(
        &last,
        "pub fn run(input: string?) -> string { \"last-result\"; }",
    )
    .expect("write final RSS script");
    let first = first.to_string_lossy().into_owned();
    let last = last.to_string_lossy().into_owned();
    let legacy = area.invoke(
        &home,
        &[
            "--script",
            &first,
            "--allow-host",
            "fixture.invalid",
            "--allow-host",
            "fixture.invalid",
            "--script",
            &last,
            "--allow-host",
            "fixture.invalid",
        ],
    );
    assert_eq!(legacy.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&legacy.stdout).contains("last-result"));
    assert!(legacy.stderr.is_empty());
    assert!(legacy.stdout.len() <= 256 * 1024);

    let explicit = area.invoke(
        &home,
        &[
            "run",
            "--script",
            &first,
            "--allow-host",
            "fixture.invalid",
            "--allow-host",
            "fixture.invalid",
            "--script",
            &last,
            "--allow-host",
            "fixture.invalid",
        ],
    );
    assert_eq!(explicit.status.code(), Some(0));
    assert_eq!(explicit.stdout, legacy.stdout);
    assert_eq!(explicit.stderr, legacy.stderr);

    let oversized = area.root.join("oversized.rss");
    let result = "x".repeat(256 * 1024);
    fs::write(
        &oversized,
        format!("pub fn run(input: string?) -> string {{ \"{result}\"; }}"),
    )
    .expect("write bounded-output RSS script");
    let oversized = oversized.to_string_lossy().into_owned();
    let rejected = area.invoke(
        &home,
        &[
            "run",
            "--script",
            &oversized,
            "--allow-host",
            "fixture.invalid",
        ],
    );
    assert_eq!(rejected.status.code(), Some(1));
    assert!(rejected.stdout.is_empty());
    assert_eq!(rejected.stderr, b"cli_output_closed\n");

    let private_path = area.root.join("PRIVATE_SCRIPT_PATH_MARKER.rss");
    fs::write(
        &private_path,
        "pub fn run(input: string?) -> int { PRIVATE_SOURCE_MARKER; }",
    )
    .expect("write invalid private RSS source");
    let private_path = private_path.to_string_lossy().into_owned();
    let compile_failure = area.invoke(
        &home,
        &[
            "run",
            "--script",
            &private_path,
            "--allow-host",
            "fixture.invalid",
        ],
    );
    assert_eq!(compile_failure.status.code(), Some(1));
    assert!(compile_failure.stdout.is_empty());
    assert_eq!(compile_failure.stderr, b"agent_compile_failed\n");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&compile_failure.stdout),
        String::from_utf8_lossy(&compile_failure.stderr)
    );
    assert!(!combined.contains("PRIVATE_SCRIPT_PATH_MARKER"));
    assert!(!combined.contains("PRIVATE_SOURCE_MARKER"));
}

#[cfg(target_os = "linux")]
fn caught_signal_mask(pid: u32) -> Option<u64> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let value = status.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name == "SigCgt").then_some(value.trim())
    })?;
    u64::from_str_radix(value, 16).ok()
}

#[cfg(target_os = "linux")]
fn cpu_ticks(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    let user: u64 = fields.get(11)?.parse().ok()?;
    let system: u64 = fields.get(12)?.parse().ok()?;
    Some(user + system)
}

#[cfg(target_os = "linux")]
#[test]
fn actual_sigint_cancels_the_active_run_and_reaps_its_process_group() {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let area = TestArea::new("sigint");
    let home = area.home("home");
    let before_entries = directory_entries(&home);
    let before_config = fs::read(home.join("config.yaml")).expect("snapshot config");
    let before_auth = fs::read(home.join("auth.yaml")).expect("snapshot auth");
    let script = area.root.join("cpu-loop.rss");
    fs::write(
        &script,
        "pub fn run(input: string?) -> int { while true { 1; } 0; }",
    )
    .expect("write bounded pure CPU loop");
    let binary = area.binary();
    let args = vec![
        "--script".to_owned(),
        script.to_string_lossy().into_owned(),
        "--allow-host".to_owned(),
        "fixture.invalid".to_owned(),
    ];
    let argv: Vec<String> = std::iter::once(binary.to_string_lossy().into_owned())
        .chain(args.iter().cloned())
        .collect();
    let mut command = Command::new(&binary);
    command
        .args(&args)
        .env("RUSTSCRIPT_AGENT_HOME", &home)
        .env("HOME", area.root.join("isolated-default-home"))
        .env_remove("USERPROFILE")
        .current_dir(&area.caller)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .expect("spawn actual binary for SIGINT test");
    let pid = child.id();
    let process_group = unsafe { libc::getpgid(pid as libc::pid_t) };
    assert_eq!(
        process_group, pid as i32,
        "child owns an isolated process group"
    );
    let clock_ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    assert!(clock_ticks > 0, "read kernel CPU tick frequency");

    let readiness_deadline = Instant::now() + Duration::from_secs(20);
    let mut ready = false;
    while Instant::now() < readiness_deadline {
        if child.try_wait().expect("poll CLI readiness").is_some() {
            break;
        }
        let caught =
            caught_signal_mask(pid).is_some_and(|mask| mask & (1u64 << (libc::SIGINT - 1)) != 0);
        let active_cpu_loop = cpu_ticks(pid).is_some_and(|ticks| ticks >= clock_ticks as u64);
        if caught && active_cpu_loop {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !ready {
        let _ = child.kill();
        let output = child.wait_with_output().expect("reap unready CLI child");
        area.record(&argv, pid, &output, process_group);
        panic!("SIGINT handler and sustained RSS CPU work never became kernel-visible");
    }

    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGINT) }, 0);
    let exit_deadline = Instant::now() + Duration::from_secs(20);
    let mut exited = false;
    while Instant::now() < exit_deadline {
        if child.try_wait().expect("poll cancelled CLI exit").is_some() {
            exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !exited {
        let _ = child.kill();
        let output = child.wait_with_output().expect("reap timed-out CLI child");
        area.record(&argv, pid, &output, process_group);
        panic!("CLI did not finish bounded SIGINT cancellation");
    }
    let output = child
        .wait_with_output()
        .expect("collect cancelled CLI output");
    area.record(&argv, pid, &output, process_group);
    assert_eq!(output.status.code(), Some(130));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"agent_cancelled\n");
    assert_redacted(&output, &home);
    assert_eq!(directory_entries(&home), before_entries);
    assert_eq!(
        fs::read(home.join("config.yaml")).expect("config unchanged"),
        before_config
    );
    assert_eq!(
        fs::read(home.join("auth.yaml")).expect("auth unchanged"),
        before_auth
    );
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "CLI process was reaped"
    );
    assert_eq!(
        unsafe { libc::kill(-(process_group as libc::pid_t), 0) },
        -1,
        "no worker or child process remains in the isolated group"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
}

#[test]
fn parser_help_and_literal_values_are_redacted_without_home_resolution() {
    let area = TestArea::new("parse-help");
    let help = area.invoke_without_home(&["--help"]);
    assert_eq!(help.status.code(), Some(0));
    assert_eq!(help.stderr, b"");
    assert_eq!(
        String::from_utf8(help.stdout.clone()).expect("help output"),
        format!("{}\n", rustscript_agent::cli::cli_usage())
    );
    assert!(!area.root.join("isolated-default-home").exists());

    let no_args = area.invoke_without_home(&[]);
    assert_eq!(no_args.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&no_args.stderr).starts_with("cli_arguments_invalid\nUsage:"));
    assert!(no_args.stdout.is_empty());
    let invalid_home = area.invoke_without_home(&["auth", "status"]);
    assert_eq!(invalid_home.status.code(), Some(1));
    assert!(invalid_home.stdout.is_empty());
    assert_eq!(invalid_home.stderr, b"cli_home_invalid\n");

    for args in [
        &["--private-argv-marker"][..],
        &["auth", "status", "provider", "extra"][..],
        &["auth", "login"][..],
        &["auth", "login", "bad\nselector"][..],
    ] {
        let output = area.invoke_without_home(args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.starts_with("cli_arguments_invalid\nUsage:"));
        assert!(!stderr.contains("private-argv-marker"));
        assert!(!stderr.contains("bad\nselector"));
    }

    let literal_home = area.home("literal-selector-home");
    let literal_selector = area.invoke(&literal_home, &["auth", "login", "--help"]);
    assert_eq!(literal_selector.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&literal_selector.stdout).contains("unsupported_operation"));
    assert!(String::from_utf8_lossy(&literal_selector.stderr).contains("unsupported_operation"));
    assert!(!String::from_utf8_lossy(&literal_selector.stdout).contains("Usage:"));

    let config_path = area.invoke(&literal_home, &["config", "path"]);
    assert_eq!(config_path.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&config_path.stdout).contains("unsupported_operation"));
    assert!(String::from_utf8_lossy(&config_path.stderr).contains("unsupported_operation"));
    assert!(
        !String::from_utf8_lossy(&config_path.stdout)
            .contains(&literal_home.to_string_lossy().to_string())
    );

    fs::write(
        area.caller.join("--help"),
        "pub fn run(input: string?) -> string { \"literal-file\"; }",
    )
    .expect("write extensionless help-looking script");
    let literal_script =
        area.invoke_without_home(&["--script", "--help", "--allow-host", "fixture.invalid"]);
    assert_eq!(literal_script.status.code(), Some(1));
    assert_eq!(literal_script.stderr, b"agent_compile_failed\n");
    assert!(!String::from_utf8_lossy(&literal_script.stdout).contains("Usage:"));
}

#[cfg(target_os = "linux")]
#[test]
fn failed_stdout_sink_returns_the_static_output_error_without_panicking() {
    let area = TestArea::new("closed-output");
    let binary = area.binary();
    let argv = vec![binary.to_string_lossy().into_owned(), "--help".to_owned()];
    let full = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("open real failing output sink");
    let mut command = Command::new(&binary);
    command
        .arg("--help")
        .env("RUSTSCRIPT_AGENT_HOME", "")
        .env("HOME", area.root.join("isolated-default-home"))
        .env_remove("USERPROFILE")
        .current_dir(&area.caller)
        .stdout(Stdio::from(full))
        .stderr(Stdio::piped());
    let group = unsafe { libc::getpgid(0) };
    let child = command.spawn().expect("spawn CLI with failing stdout");
    let pid = child.id();
    let output = child
        .wait_with_output()
        .expect("collect output sink failure");
    area.record(&argv, pid, &output, group);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stderr, b"cli_output_closed\n");
}
