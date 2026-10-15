use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

#[cfg(any(
    feature = "default",
    all(target_os = "linux", feature = "config-fixture")
))]
use std::io::Read;
#[cfg(all(target_os = "linux", feature = "config-fixture"))]
use std::net::TcpListener;
#[cfg(all(target_os = "linux", feature = "config-fixture"))]
use std::process::Child;
#[cfg(all(target_os = "linux", feature = "config-fixture"))]
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
#[cfg(all(target_os = "linux", feature = "config-fixture"))]
use std::thread;
#[cfg(all(target_os = "linux", feature = "config-fixture"))]
use std::time::{Duration, Instant};
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

    fn invoke_binary(&self, binary: &Path, home: &Path, args: &[&str]) -> Output {
        self.invoke_configured(binary, Some(home), args)
    }

    fn invoke_without_home(&self, args: &[&str]) -> Output {
        let binary = self.binary();
        self.invoke_configured(&binary, None, args)
    }

    /// Invokes the actual executable with the override variables removed, so home
    /// resolution falls through to a real `$HOME/.rustscript-agent` default. This is
    /// deliberately distinct from `invoke_without_home`, which sets an empty override.
    fn invoke_absent_override(&self, args: &[&str]) -> Output {
        let binary = self.binary();
        let argv: Vec<String> = std::iter::once(binary.to_string_lossy().into_owned())
            .chain(args.iter().map(|arg| (*arg).to_owned()))
            .collect();
        let mut command = Command::new(&binary);
        command
            .args(args)
            .env("HOME", self.root.join("isolated-default-home"))
            .env_remove("RUSTSCRIPT_AGENT_HOME")
            .env_remove("USERPROFILE")
            .current_dir(&self.caller)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        self.run_recorded(command, &argv)
    }

    fn invoke_configured(&self, binary: &Path, home: Option<&Path>, args: &[&str]) -> Output {
        let binary = binary.to_path_buf();
        let argv: Vec<String> = std::iter::once(binary.to_string_lossy().into_owned())
            .chain(args.iter().map(|arg| (*arg).to_owned()))
            .collect();
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
        self.run_recorded(command, &argv)
    }

    fn run_recorded(&self, mut command: Command, argv: &[String]) -> Output {
        let group = unsafe { libc::getpgid(0) };
        let child = command
            .spawn()
            .expect("spawn actual rustscript-agent executable");
        let pid = child.id();
        let output = child
            .wait_with_output()
            .expect("wait for actual CLI process");
        self.record(argv, pid, &output, group);
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
fn copied_binary_runs_login_pre_oauth_gates_outside_checkout_without_auth_mutation() {
    let area = TestArea::new("login-pre-oauth-outside-checkout");
    assert!(!area.caller.starts_with(env!("CARGO_MANIFEST_DIR")));
    let staged = stage_executable_copy(&area.binary(), &area.caller.join("rustscript-agent"));
    let copied_binary = staged.path;

    let unknown = area.home("unknown-provider-home");
    fs::remove_file(unknown.join("auth.yaml")).expect("remove auth fixture");

    let unsupported = area.home("unsupported-flow-home");
    fs::remove_file(unsupported.join("auth.yaml")).expect("remove auth fixture");
    let mut unsupported_config: serde_yaml::Value =
        serde_yaml::from_slice(&fs::read(unsupported.join("config.yaml")).expect("read config"))
            .expect("parse config");
    unsupported_config["providers"]["openai-codex"]["oauth"]["flow"] =
        serde_yaml::Value::String("browser".into());
    fs::write(
        unsupported.join("config.yaml"),
        serde_yaml::to_string(&unsupported_config).expect("serialize unsupported flow"),
    )
    .expect("write unsupported flow");

    let missing_auth = area.home("missing-auth-home");
    fs::remove_file(missing_auth.join("auth.yaml")).expect("remove auth fixture");
    let mut missing_config: serde_yaml::Value =
        serde_yaml::from_slice(&fs::read(missing_auth.join("config.yaml")).expect("read config"))
            .expect("parse config");
    let mut missing_provider = missing_config["providers"]["openai-codex"].clone();
    missing_provider
        .as_mapping_mut()
        .expect("provider mapping")
        .remove(serde_yaml::Value::String("auth".into()));
    missing_config["providers"]
        .as_mapping_mut()
        .expect("providers mapping")
        .insert(
            serde_yaml::Value::String("secondary-missing-auth".into()),
            missing_provider,
        );
    fs::write(
        missing_auth.join("config.yaml"),
        serde_yaml::to_string(&missing_config).expect("serialize missing auth provider"),
    )
    .expect("write missing auth provider");

    let null_auth = area.home("null-auth-home");
    fs::remove_file(null_auth.join("auth.yaml")).expect("remove auth fixture");
    let mut null_config: serde_yaml::Value =
        serde_yaml::from_slice(&fs::read(null_auth.join("config.yaml")).expect("read config"))
            .expect("parse config");
    let mut null_provider = null_config["providers"]["openai-codex"].clone();
    null_provider["auth"] = serde_yaml::Value::Null;
    null_config["providers"]
        .as_mapping_mut()
        .expect("providers mapping")
        .insert(
            serde_yaml::Value::String("secondary-null-auth".into()),
            null_provider,
        );
    fs::write(
        null_auth.join("config.yaml"),
        serde_yaml::to_string(&null_config).expect("serialize null auth provider"),
    )
    .expect("write null auth provider");

    for (home, provider, expected) in [
        (&unknown, "unknown-provider", "provider_not_found"),
        (&unsupported, "openai-codex", "login_flow_unsupported"),
        (
            &missing_auth,
            "secondary-missing-auth",
            "credential_id_required",
        ),
        (&null_auth, "secondary-null-auth", "credential_id_required"),
    ] {
        let config_before = fs::read(home.join("config.yaml")).expect("snapshot config bytes");
        let entries_before = directory_entries(home);
        assert_eq!(entries_before, ["config.yaml"]);
        let output = area.invoke_binary(&copied_binary, home, &["auth", "login", provider]);
        assert_eq!(output.status.code(), Some(1), "stderr={:?}", output.stderr);
        assert_eq!(output.stdout, format!("{expected}\n").as_bytes());
        assert_eq!(output.stderr, format!("{expected}\n").as_bytes());
        assert_redacted(&output, home);
        assert_eq!(directory_entries(home), entries_before);
        assert_eq!(
            fs::read(home.join("config.yaml")).expect("config unchanged"),
            config_before
        );
        assert!(
            !home.join("auth.yaml").exists(),
            "pre-OAuth failure created auth.yaml"
        );
        assert!(
            !home.join("auth.yaml.lock").exists(),
            "pre-OAuth failure created auth lock"
        );
    }
}

#[test]
fn installed_config_path_reports_lexical_path_without_reading_or_creating_config() {
    let area = TestArea::new("config-path-lexical");
    let home = area.home("existing-home");
    let before_entries = directory_entries(&home);
    let before_config = fs::read(home.join("config.yaml")).expect("snapshot config bytes");
    let before_auth = fs::read(home.join("auth.yaml")).expect("snapshot auth bytes");

    let existing = area.invoke(&home, &["config", "path"]);
    assert_eq!(
        existing.status.code(),
        Some(0),
        "config path stderr={}",
        String::from_utf8_lossy(&existing.stderr)
    );
    assert_eq!(
        existing.stdout,
        format!("{}\n", home.join("config.yaml").to_string_lossy()).into_bytes()
    );
    assert!(existing.stderr.is_empty());
    assert_eq!(directory_entries(&home), before_entries);
    assert_eq!(
        fs::read(home.join("config.yaml")).expect("config remains unchanged"),
        before_config
    );
    assert_eq!(
        fs::read(home.join("auth.yaml")).expect("auth remains unchanged"),
        before_auth
    );

    // An isolated existing-but-empty home must report the exact lexical path with no
    // fixture copied in and no entries created.
    let empty_home = area.root.join("empty-existing-home");
    fs::create_dir(&empty_home).expect("create isolated empty home");
    let empty_before = directory_entries(&empty_home);
    assert!(empty_before.is_empty(), "empty home starts empty");

    let empty = area.invoke(&empty_home, &["config", "path"]);
    assert_eq!(
        empty.status.code(),
        Some(0),
        "empty home stderr={}",
        String::from_utf8_lossy(&empty.stderr)
    );
    assert_eq!(
        empty.stdout,
        format!("{}\n", empty_home.join("config.yaml").to_string_lossy()).into_bytes()
    );
    assert!(empty.stderr.is_empty());
    assert_eq!(directory_entries(&empty_home), empty_before);

    // A legal lexical name with spaces, a quote and a backslash must stay byte-exact;
    // the missing home and its missing parent are never created.
    let missing_parent = area.root.join("nested-legal");
    let missing_home = missing_parent.join(r#"space "quoted" and \backslash"#);
    let missing = area.invoke(&missing_home, &["config", "path"]);
    assert_eq!(
        missing.status.code(),
        Some(0),
        "config path stderr={}",
        String::from_utf8_lossy(&missing.stderr)
    );
    assert_eq!(
        missing.stdout,
        format!(
            "{}\n",
            missing_home
                .join("config.yaml")
                .to_str()
                .expect("legal UTF-8 home")
        )
        .into_bytes()
    );
    assert!(missing.stderr.is_empty());
    assert!(
        !missing_home.exists(),
        "config path must not create the missing home"
    );
    assert!(
        !missing_parent.exists(),
        "config path must not create missing parents"
    );
    assert!(!area.root.join("isolated-default-home").exists());
}

#[test]
fn installed_config_path_succeeds_over_corrupt_and_directory_config_without_traversal() {
    let area = TestArea::new("config-path-opaque");

    // Corrupt, non-UTF-8 config.yaml and auth.yaml must not affect the lexical path.
    let corrupt = area.root.join("corrupt-home");
    fs::create_dir_all(&corrupt).expect("corrupt home");
    fs::write(corrupt.join("config.yaml"), b"invalid: [config\xffbytes").expect("corrupt config");
    fs::write(corrupt.join("auth.yaml"), b"invalid: [auth\xfebytes").expect("corrupt auth");
    let config_before = fs::read(corrupt.join("config.yaml")).expect("snapshot config");
    let auth_before = fs::read(corrupt.join("auth.yaml")).expect("snapshot auth");
    let entries_before = directory_entries(&corrupt);

    let output = area.invoke(&corrupt, &["config", "path"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "corrupt path stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        format!("{}\n", corrupt.join("config.yaml").to_string_lossy()).into_bytes()
    );
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.windows(7).any(|w| w == b"config\xff"));
    assert_eq!(directory_entries(&corrupt), entries_before);
    assert_eq!(
        fs::read(corrupt.join("config.yaml")).expect("config unchanged"),
        config_before
    );
    assert_eq!(
        fs::read(corrupt.join("auth.yaml")).expect("auth unchanged"),
        auth_before
    );

    // An opaque directory occupying the config.yaml entry must also succeed with no
    // content traversal and no entry changes.
    let opaque = area.root.join("opaque-home");
    fs::create_dir_all(opaque.join("config.yaml")).expect("directory-shaped config");
    fs::create_dir_all(opaque.join("auth.yaml")).expect("directory-shaped auth");
    let opaque_entries_before = directory_entries(&opaque);
    let opaque = opaque
        .canonicalize()
        .expect("canonical opaque home for lexical check");

    let output = area.invoke(&opaque, &["config", "path"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "opaque directory path stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        format!("{}\n", opaque.join("config.yaml").to_string_lossy()).into_bytes()
    );
    assert!(output.stderr.is_empty());
    assert_eq!(directory_entries(&opaque), opaque_entries_before);
    assert!(opaque.join("config.yaml").is_dir());
    assert!(opaque.join("auth.yaml").is_dir());
}

#[cfg(unix)]
#[test]
fn installed_config_path_reports_symlink_home_lexically_without_canonicalizing() {
    let area = TestArea::new("config-path-symlink");
    let target = area.root.join("target-home");
    fs::create_dir_all(&target).expect("symlink target home");
    fs::write(target.join("config.yaml"), b"opaque: [target bytes").expect("target config");
    let target_config_before = fs::read(target.join("config.yaml")).expect("target config bytes");
    let target_entries_before = directory_entries(&target);

    let link = area.root.join("alias-home");
    std::os::unix::fs::symlink(&target, &link).expect("create symlink home");
    let link_target_before =
        fs::read_link(&link).expect("snapshot symlink target before invocation");

    let output = area.invoke(&link, &["config", "path"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "symlink path stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The exact symlink spelling is reported, with no realpath canonicalization.
    assert_eq!(
        output.stdout,
        format!("{}\n", link.join("config.yaml").to_string_lossy()).into_bytes()
    );
    assert!(output.stderr.is_empty());
    // The link still resolves to the identical target; it was not replaced or retargeted.
    assert_eq!(
        fs::read_link(&link).expect("symlink target after invocation"),
        link_target_before
    );
    assert_eq!(directory_entries(&target), target_entries_before);
    assert_eq!(
        fs::read(target.join("config.yaml")).expect("target config unchanged"),
        target_config_before
    );
}

#[test]
fn installed_config_path_resolves_absent_override_to_default_home() {
    let area = TestArea::new("config-path-absent-override");
    let default_home = area.root.join("isolated-default-home");

    // An absent RUSTSCRIPT_AGENT_HOME override falls through to HOME/.rustscript-agent.
    let output = area.invoke_absent_override(&["config", "path"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "absent override stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        format!(
            "{}\n",
            default_home
                .join(".rustscript-agent")
                .join("config.yaml")
                .to_string_lossy()
        )
        .into_bytes()
    );
    assert!(output.stderr.is_empty());
    assert!(
        !default_home.exists(),
        "absent-override default lookup must not create the default home"
    );
    assert!(!default_home.join(".rustscript-agent").exists());

    // An empty override is a distinct static failure and must not fall back to HOME.
    let empty = area.invoke_without_home(&["config", "path"]);
    assert_eq!(empty.status.code(), Some(1));
    assert!(empty.stdout.is_empty());
    assert_eq!(empty.stderr, b"cli_home_invalid\n");
    assert!(
        !default_home.exists(),
        "empty-override failure must not create the default home"
    );
}

#[test]
fn installed_config_path_rejects_invalid_home_and_path_without_creation() {
    let area = TestArea::new("config-path-invalid");
    let caller_entries_before = directory_entries(&area.caller);

    // A relative home is rejected before any observation; the caller-relative
    // target must stay absent and the caller entries unchanged.
    let relative_home = PathBuf::from("relative-home");
    let relative_target = area.caller.join(&relative_home);
    assert!(!relative_target.exists());
    let relative = area.invoke(&relative_home, &["config", "path"]);
    assert_eq!(
        relative.status.code(),
        Some(1),
        "relative home stderr={}",
        String::from_utf8_lossy(&relative.stderr)
    );
    assert!(relative.stdout.is_empty());
    assert_eq!(relative.stderr, b"cli_home_invalid\n");
    assert!(
        !relative_target.exists(),
        "relative home must not be created"
    );
    assert_eq!(directory_entries(&area.caller), caller_entries_before);

    // A parent-directory component is rejected; neither the absent parent nor the
    // potentially normalized sibling target may be created.
    let absent_parent = area.root.join("absent-parent");
    let parent_home = absent_parent.join("..").join("outside");
    let normalized_sibling = area.root.join("outside");
    assert!(!absent_parent.exists());
    assert!(!normalized_sibling.exists());
    let parent = area.invoke(&parent_home, &["config", "path"]);
    assert_eq!(
        parent.status.code(),
        Some(1),
        "parent component stderr={}",
        String::from_utf8_lossy(&parent.stderr)
    );
    assert!(parent.stdout.is_empty());
    assert_eq!(parent.stderr, b"cli_home_invalid\n");
    assert!(!absent_parent.exists(), "absent parent must not be created");
    assert!(
        !normalized_sibling.exists(),
        "normalized sibling target must not be created"
    );

    // Native text bounds reject control characters, oversize and non-UTF-8 paths with
    // the static invalid_path failure and no echoed bytes or created homes. Every such
    // fixture lives below one owned, never-created parent.
    let invalid_parent = area.root.join("absent-invalid-parent");
    assert!(!invalid_parent.exists());

    let control_home = invalid_parent.join(format!("line{}break", '\n'));
    let control = area.invoke(&control_home, &["config", "path"]);
    assert_eq!(control.status.code(), Some(1));
    assert!(control.stdout.is_empty());
    assert_eq!(control.stderr, b"invalid_path\n");
    assert!(!String::from_utf8_lossy(&control.stderr).contains("line"));
    assert!(!control_home.exists(), "control home must not be created");
    assert!(
        !invalid_parent.exists(),
        "control parent must not be created"
    );

    let long_home = (0..11).fold(invalid_parent.clone(), |path, _| path.join("x".repeat(220)));
    assert!(long_home.join("config.yaml").as_os_str().len() > 2048);
    let long = area.invoke(&long_home, &["config", "path"]);
    assert_eq!(long.status.code(), Some(1));
    assert!(long.stdout.is_empty());
    assert_eq!(long.stderr, b"invalid_path\n");
    // Asserting the first absent ancestor is sufficient for the oversize path.
    assert!(
        !invalid_parent.exists(),
        "oversize parent must not be created"
    );

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut bytes = invalid_parent.as_os_str().as_encoded_bytes().to_vec();
        bytes.extend_from_slice(b"/invalid-\xff-home");
        let invalid_utf8 = PathBuf::from(std::ffi::OsString::from_vec(bytes));
        assert!(!invalid_utf8.exists());
        assert!(fs::symlink_metadata(&invalid_utf8).is_err());
        let report = area.invoke(&invalid_utf8, &["config", "path"]);
        assert_eq!(report.status.code(), Some(1));
        assert!(report.stdout.is_empty());
        assert_eq!(report.stderr, b"invalid_path\n");
        assert!(!String::from_utf8_lossy(&report.stderr).contains("invalid-"));
        assert!(
            !invalid_utf8.exists(),
            "invalid-UTF-8 home must not be created"
        );
        assert!(
            fs::symlink_metadata(&invalid_utf8).is_err(),
            "invalid-UTF-8 home must not exist after the run"
        );
        assert!(
            !invalid_parent.exists(),
            "invalid-UTF-8 parent must not be created"
        );
    }

    assert!(!area.root.join("isolated-default-home").exists());
}

#[test]
fn installed_config_path_rejects_malformed_argv_without_resolving_home() {
    let area = TestArea::new("config-path-argv");
    let caller_entries_before = directory_entries(&area.caller);
    let relative_home = PathBuf::from("argv-invalid-home");
    let relative_target = area.caller.join(&relative_home);

    // `config path` with a trailing argument is an argv-shape failure before any home
    // or path resolution. An explicitly INVALID relative home proves the ordering:
    // if home resolution ran first this would yield exit1 cli_home_invalid instead of
    // the argv failure, so the exit2/usage assertion is load-bearing.
    let output = area.invoke(&relative_home, &["config", "path", "extra"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("cli_arguments_invalid\nUsage:"));
    assert!(!stderr.contains("extra"));
    assert!(!stderr.contains("cli_home_invalid"));
    assert!(!stderr.contains(relative_home.to_str().expect("relative home is ASCII")));
    assert!(
        !relative_target.exists(),
        "malformed argv must not create the relative home"
    );
    assert_eq!(directory_entries(&area.caller), caller_entries_before);
    assert!(!area.root.join("isolated-default-home").exists());
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

    let before_entries = directory_entries(&home);
    let before_config = fs::read(home.join("config.yaml")).expect("snapshot config");
    let path = area.invoke_binary(&installed, &home, &["config", "path"]);
    assert_eq!(path.status.code(), Some(0));
    assert_eq!(
        path.stdout,
        format!("{}\n", home.join("config.yaml").to_string_lossy()).into_bytes()
    );
    assert!(path.stderr.is_empty());
    assert_eq!(directory_entries(&home), before_entries);
    assert_eq!(
        fs::read(home.join("config.yaml")).expect("config unchanged"),
        before_config
    );
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
    assert_eq!(literal_selector.stdout, b"provider_not_found\n");
    assert_eq!(literal_selector.stderr, b"provider_not_found\n");
    assert!(!String::from_utf8_lossy(&literal_selector.stdout).contains("Usage:"));

    let config_path = area.invoke(&literal_home, &["config", "path"]);
    assert_eq!(config_path.status.code(), Some(0));
    assert_eq!(
        config_path.stdout,
        format!("{}\n", literal_home.join("config.yaml").to_string_lossy()).into_bytes()
    );
    assert!(config_path.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&config_path.stdout).contains("Usage:"));

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

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
#[derive(Debug)]
enum TrustServerEvent {
    TcpAccepted,
    Handshake {
        inbound_bytes: usize,
        outbound_bytes: usize,
        completed: bool,
    },
}

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
struct ObservedTcpStream {
    stream: tokio::net::TcpStream,
    inbound_bytes: Arc<AtomicUsize>,
    outbound_bytes: Arc<AtomicUsize>,
}

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
impl tokio::io::AsyncRead for ObservedTcpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = std::pin::Pin::new(&mut this.stream).poll_read(context, buffer);
        if let std::task::Poll::Ready(Ok(())) = &result {
            this.inbound_bytes
                .fetch_add(buffer.filled().len() - before, Ordering::Relaxed);
        }
        result
    }
}

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
impl tokio::io::AsyncWrite for ObservedTcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.stream).poll_write(context, bytes) {
            std::task::Poll::Ready(Ok(written)) => {
                this.outbound_bytes.fetch_add(written, Ordering::Relaxed);
                std::task::Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
fn untrusted_tls_server_config() -> Arc<rustls::ServerConfig> {
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
            .expect("generate local self-signed certificate");
    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der())
                    .into(),
            )
            .expect("configure local TLS server"),
    )
}

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
fn spawn_trust_server(
    listener: TcpListener,
    tls_config: Arc<rustls::ServerConfig>,
) -> (
    mpsc::Receiver<TrustServerEvent>,
    Arc<AtomicBool>,
    thread::JoinHandle<()>,
) {
    let (sender, receiver) = mpsc::sync_channel(2);
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let worker = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("create bounded local TLS fixture runtime");
        runtime.block_on(async move {
            let accept_deadline = Instant::now() + Duration::from_secs(10);
            let tcp = loop {
                if worker_stop.load(Ordering::Acquire) || Instant::now() >= accept_deadline {
                    return;
                }
                match listener.accept() {
                    Ok((tcp, _)) => break tcp,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    Err(_) => return,
                }
            };
            let accepted_at = Instant::now();
            let _ = sender.send(TrustServerEvent::TcpAccepted);
            if tcp.set_nonblocking(true).is_err() {
                return;
            }
            let Ok(stream) = tokio::net::TcpStream::from_std(tcp) else {
                return;
            };
            let inbound_bytes = Arc::new(AtomicUsize::new(0));
            let outbound_bytes = Arc::new(AtomicUsize::new(0));
            let observed = ObservedTcpStream {
                stream,
                inbound_bytes: Arc::clone(&inbound_bytes),
                outbound_bytes: Arc::clone(&outbound_bytes),
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
            let deadline = tokio::time::Instant::from_std(accepted_at + Duration::from_secs(10));
            let handshake = tokio::time::timeout_at(deadline, acceptor.accept(observed)).await;
            let _ = sender.send(TrustServerEvent::Handshake {
                inbound_bytes: inbound_bytes.load(Ordering::Relaxed),
                outbound_bytes: outbound_bytes.load(Ordering::Relaxed),
                completed: matches!(handshake, Ok(Ok(_))),
            });
        });
    });
    (receiver, stop, worker)
}

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
#[derive(Debug)]
enum StallServerEvent {
    TcpAccepted,
    ClientHello([u8; 5]),
    PeerClosed { closed: bool, trailing_bytes: usize },
    ReadFailed,
}

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
fn spawn_stalled_tls_server(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
) -> (mpsc::Receiver<StallServerEvent>, thread::JoinHandle<()>) {
    let (sender, receiver) = mpsc::sync_channel(3);
    let worker = thread::spawn(move || {
        let accept_deadline = Instant::now() + Duration::from_secs(10);
        let mut tcp = loop {
            if stop.load(Ordering::Acquire) || Instant::now() >= accept_deadline {
                return;
            }
            match listener.accept() {
                Ok((tcp, _)) => break tcp,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        };
        let accepted_at = Instant::now();
        let _ = sender.send(StallServerEvent::TcpAccepted);
        if tcp.set_read_timeout(Some(Duration::from_secs(5))).is_err() {
            let _ = sender.send(StallServerEvent::ReadFailed);
            return;
        }
        let mut client_hello_record = [0u8; 5];
        if tcp.read_exact(&mut client_hello_record).is_err() {
            let _ = sender.send(StallServerEvent::ReadFailed);
            return;
        }
        let _ = sender.send(StallServerEvent::ClientHello(client_hello_record));

        let mut trailing_bytes = 0usize;
        let close_deadline = accepted_at + Duration::from_secs(10);
        let mut buffer = [0u8; 1024];
        let closed = loop {
            let remaining = close_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break false;
            }
            if tcp.set_read_timeout(Some(remaining)).is_err() {
                break false;
            }
            match tcp.read(&mut buffer) {
                Ok(0) => break true,
                Ok(read) => {
                    trailing_bytes = trailing_bytes.saturating_add(read);
                    if trailing_bytes > 64 * 1024 {
                        break false;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break false;
                }
                Err(_) => break false,
            }
        };
        let _ = sender.send(StallServerEvent::PeerClosed {
            closed,
            trailing_bytes,
        });
    });
    (receiver, worker)
}

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
fn local_listener() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral loopback listener");
    listener
        .set_nonblocking(true)
        .expect("make loopback listener nonblocking");
    listener
}

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
fn device_login_home(area: &TestArea, label: &str, port: u16) -> PathBuf {
    let home = area.root.join(label);
    fs::create_dir(&home).expect("create fresh local-login home");
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/codex_device/config.yaml");
    let mut config: serde_yaml::Value =
        serde_yaml::from_slice(&fs::read(fixture).expect("read device-login fixture"))
            .expect("parse device-login fixture");
    let authority = format!("https://127.0.0.1:{port}");
    config["providers"]["openai-codex"]["oauth"]["issuer"] =
        serde_yaml::Value::String(authority.clone());
    config["providers"]["openai-codex"]["oauth"]["token_endpoint"] =
        serde_yaml::Value::String(format!("{authority}/oauth/token"));
    config["providers"]["openai-codex"]["oauth"]["redirect_uri"] =
        serde_yaml::Value::String(format!("{authority}/deviceauth/callback"));
    fs::write(
        home.join("config.yaml"),
        serde_yaml::to_string(&config).expect("serialize local device-login config"),
    )
    .expect("write local device-login config");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700))
            .expect("restrict local-login home");
        fs::set_permissions(home.join("config.yaml"), fs::Permissions::from_mode(0o600))
            .expect("restrict local-login config");
    }
    home
}

/// Test-only executable staging provenance: the PID of the process that opened
/// the destination writer. On Linux the writer lives only in an owned copier
/// child's FD table, never in the shared harness parent FD table.
struct StagedExecutable {
    path: PathBuf,
    writer_pid: u32,
}

#[cfg(target_os = "linux")]
fn stage_executable_copy(source: &Path, destination: &Path) -> StagedExecutable {
    const COPIERS: [&str; 2] = ["/bin/cp", "/usr/bin/cp"];
    let copier = COPIERS
        .iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.is_file())
        .expect("an available system file copier for executable staging");
    let mut child = Command::new(&copier)
        .arg(source)
        .arg(destination)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn owned executable staging copier");
    let writer_pid = child.id();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match child.try_wait().expect("poll owned staging copier") {
            Some(status) => {
                assert!(
                    status.success(),
                    "owned staging copier exited with {status}"
                );
                break;
            }
            None => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("owned staging copier timed out");
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(source)
            .expect("stat staging source")
            .permissions()
            .mode();
        fs::set_permissions(destination, fs::Permissions::from_mode(mode))
            .expect("mirror staged executable mode");
    }
    StagedExecutable {
        path: destination.to_path_buf(),
        writer_pid,
    }
}

#[cfg(not(target_os = "linux"))]
fn stage_executable_copy(source: &Path, destination: &Path) -> StagedExecutable {
    fs::copy(source, destination).expect("stage the actual executable outside checkout");
    StagedExecutable {
        path: destination.to_path_buf(),
        writer_pid: std::process::id(),
    }
}

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
fn copied_binary(area: &TestArea) -> PathBuf {
    stage_executable_copy(&area.binary(), &area.caller.join("rustscript-agent")).path
}

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
fn spawn_copied_login(area: &TestArea, binary: &Path, home: &Path) -> (Child, Vec<String>, i32) {
    use std::os::unix::process::CommandExt;

    let args = ["auth", "login", "openai-codex"];
    let argv: Vec<String> = std::iter::once(binary.to_string_lossy().into_owned())
        .chain(args.iter().map(|arg| (*arg).to_owned()))
        .collect();
    let mut command = Command::new(binary);
    command
        .args(args)
        .env("RUSTSCRIPT_AGENT_HOME", home)
        .env("HOME", area.root.join("isolated-default-home"))
        .env_remove("USERPROFILE")
        .current_dir(&area.caller)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let child = command.spawn().expect("spawn copied auth.login executable");
    let process_group = unsafe { libc::getpgid(child.id() as libc::pid_t) };
    assert_eq!(
        process_group,
        child.id() as i32,
        "CLI owns its process group"
    );
    (child, argv, process_group)
}

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().expect("poll copied CLI child").is_some() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
fn finish_copied_child(
    area: &TestArea,
    mut child: Child,
    argv: &[String],
    process_group: i32,
    timeout: Duration,
) -> Output {
    let exited = wait_for_child_exit(&mut child, timeout);
    if !exited {
        // SAFETY: the isolated process group is owned by this test invocation.
        let _ = unsafe { libc::kill(-(process_group as libc::pid_t), libc::SIGKILL) };
        let reaped = wait_for_child_exit(&mut child, Duration::from_secs(2));
        assert!(reaped, "timed-out copied CLI process group was not reaped");
    }
    let pid = child.id();
    let output = child
        .wait_with_output()
        .expect("collect bounded copied CLI output");
    area.record(argv, pid, &output, process_group);
    output
}

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
fn wait_for_trust_event(
    receiver: &mpsc::Receiver<TrustServerEvent>,
    child: &mut Child,
    stop: &AtomicBool,
) -> Option<TrustServerEvent> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match receiver.try_recv() {
            Ok(event) => return Some(event),
            Err(mpsc::TryRecvError::Disconnected) => return None,
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if child.try_wait().expect("poll copied CLI startup").is_some() {
            stop.store(true, Ordering::Release);
            return None;
        }
        if Instant::now() >= deadline {
            stop.store(true, Ordering::Release);
            return None;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
fn wait_for_stall_event(
    receiver: &mpsc::Receiver<StallServerEvent>,
    child: &mut Child,
    stop: &AtomicBool,
) -> Option<StallServerEvent> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match receiver.try_recv() {
            Ok(event) => return Some(event),
            Err(mpsc::TryRecvError::Disconnected) => return None,
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if child.try_wait().expect("poll copied CLI startup").is_some() {
            stop.store(true, Ordering::Release);
            return None;
        }
        if Instant::now() >= deadline {
            stop.store(true, Ordering::Release);
            return None;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

// These native loopback TLS tests require the explicit local-provider fixture feature.
#[cfg(all(target_os = "linux", feature = "config-fixture"))]
#[test]
fn copied_login_reaches_untrusted_local_tls_and_keeps_home_unchanged() {
    let area = TestArea::new("login-untrusted-local-tls");
    assert!(!area.caller.starts_with(env!("CARGO_MANIFEST_DIR")));
    let copied = copied_binary(&area);
    let tls_config = untrusted_tls_server_config();
    let listener = local_listener();
    let port = listener.local_addr().expect("local TLS port").port();
    let home = device_login_home(&area, "fresh-home", port);
    let config_before = fs::read(home.join("config.yaml")).expect("snapshot local config");
    let entries_before = directory_entries(&home);
    assert_eq!(entries_before, ["config.yaml"]);
    let (receiver, stop, server) = spawn_trust_server(listener, tls_config);
    let (mut child, argv, process_group) = spawn_copied_login(&area, &copied, &home);

    let accepted = wait_for_trust_event(&receiver, &mut child, &stop);
    match accepted {
        Some(TrustServerEvent::TcpAccepted) => (),
        other => {
            let output =
                finish_copied_child(&area, child, &argv, process_group, Duration::from_secs(10));
            stop.store(true, Ordering::Release);
            server.join().expect("join stopped trust server");
            assert_eq!(output.status.code(), Some(1));
            assert_eq!(output.stdout, b"start_transport_failed\n");
            assert_eq!(output.stderr, b"start_transport_failed\n");
            panic!("copied login had no real local TCP acceptance: {other:?}")
        }
    }

    let handshake = receiver.recv_timeout(Duration::from_secs(10));
    let output = finish_copied_child(&area, child, &argv, process_group, Duration::from_secs(10));
    server.join().expect("join completed untrusted TLS server");
    let handshake = match handshake {
        Ok(TrustServerEvent::Handshake {
            inbound_bytes,
            outbound_bytes,
            completed,
        }) => (inbound_bytes, outbound_bytes, completed),
        other => panic!("missing bounded TLS handshake evidence: {other:?}; {output:?}"),
    };
    let (inbound_bytes, outbound_bytes, completed) = handshake;
    assert!(inbound_bytes > 0, "server received actual TLS client bytes");
    assert!(
        outbound_bytes > 0,
        "server sent its self-signed TLS certificate"
    );
    assert!(
        !completed,
        "public-root client rejected the self-signed certificate"
    );

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"start_transport_failed\n");
    assert_eq!(output.stderr, b"start_transport_failed\n");
    assert_redacted(&output, &home);
    assert_eq!(directory_entries(&home), entries_before);
    assert_eq!(
        fs::read(home.join("config.yaml")).expect("local config remains unchanged"),
        config_before
    );
    assert!(!home.join("auth.yaml").exists());
    assert!(!home.join("auth.yaml.lock").exists());
}

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
#[test]
fn copied_login_sigint_after_tls_client_hello_returns_auth_cancelled_and_reaps_child() {
    let area = TestArea::new("login-tls-sigint");
    assert!(!area.caller.starts_with(env!("CARGO_MANIFEST_DIR")));
    let copied = copied_binary(&area);
    let listener = local_listener();
    let port = listener
        .local_addr()
        .expect("local stalled TLS port")
        .port();
    let home = device_login_home(&area, "fresh-home", port);
    let config_before = fs::read(home.join("config.yaml")).expect("snapshot local config");
    let entries_before = directory_entries(&home);
    assert_eq!(entries_before, ["config.yaml"]);
    let stop = Arc::new(AtomicBool::new(false));
    let (receiver, server) = spawn_stalled_tls_server(listener, Arc::clone(&stop));
    let (mut child, argv, process_group) = spawn_copied_login(&area, &copied, &home);
    let child_pid = child.id();

    let event = wait_for_stall_event(&receiver, &mut child, &stop);
    match event {
        Some(StallServerEvent::TcpAccepted) => (),
        other => {
            let output =
                finish_copied_child(&area, child, &argv, process_group, Duration::from_secs(10));
            stop.store(true, Ordering::Release);
            server.join().expect("join stopped stalled TLS server");
            assert_eq!(output.status.code(), Some(130));
            assert_eq!(output.stdout, b"");
            assert_eq!(output.stderr, b"auth_cancelled\n");
            panic!("copied login had no local TCP acceptance before SIGINT: {other:?}")
        }
    }
    let hello = receiver.recv_timeout(Duration::from_secs(5));
    let hello = match hello {
        Ok(event) => event,
        Err(error) => {
            let output =
                finish_copied_child(&area, child, &argv, process_group, Duration::from_secs(10));
            server
                .join()
                .expect("join stalled TLS server after ClientHello timeout");
            panic!("timed out waiting for TLS ClientHello: {error}; {output:?}")
        }
    };
    let StallServerEvent::ClientHello(record) = hello else {
        let output =
            finish_copied_child(&area, child, &argv, process_group, Duration::from_secs(10));
        server
            .join()
            .expect("join stalled TLS server after read failure");
        assert_eq!(output.status.code(), Some(130));
        assert_eq!(output.stderr, b"auth_cancelled\n");
        panic!("local server did not receive TLS ClientHello bytes")
    };
    if record[0] != 0x16 || record[1] != 0x03 {
        let output =
            finish_copied_child(&area, child, &argv, process_group, Duration::from_secs(10));
        let _ = receiver.recv_timeout(Duration::from_secs(10));
        server
            .join()
            .expect("join stalled TLS server after malformed client record");
        panic!("local server received non-TLS bytes {record:?}: {output:?}")
    }

    // SAFETY: SIGINT is sent only after the owned server accepted TCP and read TLS bytes.
    let signal_result = unsafe { libc::kill(child_pid as libc::pid_t, libc::SIGINT) };
    if signal_result != 0 {
        let output =
            finish_copied_child(&area, child, &argv, process_group, Duration::from_secs(10));
        server
            .join()
            .expect("join stalled TLS server after signal failure");
        panic!("failed to deliver SIGINT to copied CLI: {output:?}");
    }

    let output = finish_copied_child(&area, child, &argv, process_group, Duration::from_secs(10));
    let closed = receiver.recv_timeout(Duration::from_secs(10));
    server
        .join()
        .expect("join stalled TLS server after peer close");
    let closed = match closed {
        Ok(event) => event,
        Err(error) => panic!("missing bounded peer-close observation: {error}; {output:?}"),
    };
    let StallServerEvent::PeerClosed {
        closed: peer_closed,
        trailing_bytes,
    } = closed
    else {
        panic!("stalled TLS server did not observe child socket cleanup")
    };
    assert!(
        peer_closed,
        "cancelled native transport closed its TCP socket"
    );
    assert!(trailing_bytes <= 64 * 1024, "bounded TLS teardown bytes");

    assert_eq!(output.status.code(), Some(130));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"auth_cancelled\n");
    assert_redacted(&output, &home);
    assert_eq!(directory_entries(&home), entries_before);
    assert_eq!(
        fs::read(home.join("config.yaml")).expect("local config remains unchanged"),
        config_before
    );
    assert!(!home.join("auth.yaml").exists());
    assert!(!home.join("auth.yaml.lock").exists());
    assert!(
        !Path::new(&format!("/proc/{child_pid}")).exists(),
        "copied CLI process was reaped"
    );
    assert_eq!(
        unsafe { libc::kill(-(process_group as libc::pid_t), 0) },
        -1,
        "no child process remains in the isolated process group"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
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

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
fn parent_holds_writable_fd_for(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let target = fs::metadata(path).expect("stat staged destination");
    let (device, inode) = (target.dev(), target.ino());
    let handles = fs::read_dir("/proc/self/fd").expect("list harness file descriptors");
    for entry in handles {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let fd: libc::c_int = match entry.file_name().to_string_lossy().parse() {
            Ok(fd) => fd,
            Err(_) => continue,
        };
        let mut file_stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut file_stat) } != 0 {
            continue;
        }
        if file_stat.st_dev as u64 != device || file_stat.st_ino as u64 != inode {
            continue;
        }
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            continue;
        }
        let access = flags & libc::O_ACCMODE;
        if access == libc::O_WRONLY || access == libc::O_RDWR {
            return true;
        }
    }
    false
}

#[cfg(all(target_os = "linux", feature = "config-fixture"))]
#[test]
fn staged_executable_copy_is_owned_by_child_copier_without_parent_writer_fd() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let root = {
        let area = TestArea::new("login-staging-ownership");
        assert!(!area.caller.starts_with(env!("CARGO_MANIFEST_DIR")));
        let destination = area.caller.join("rustscript-agent");
        let staged = stage_executable_copy(&area.binary(), &destination);
        assert_eq!(staged.path, destination);
        // Safety property: the destination writer must live in an owned copier
        // child, never in the shared harness parent FD table.
        assert!(
            staged.writer_pid != std::process::id(),
            "staged copy writer must be an owned child, not the harness parent"
        );
        assert!(
            !Path::new(&format!("/proc/{}", staged.writer_pid)).exists(),
            "owned staging copier was reaped before returning the staged path"
        );
        let source_meta = fs::metadata(area.binary()).expect("stat Cargo executable");
        let staged_meta = fs::metadata(&destination).expect("stat staged executable");
        assert!(
            (staged_meta.dev(), staged_meta.ino()) != (source_meta.dev(), source_meta.ino()),
            "staged executable is an independent copy, not a link to the Cargo artifact"
        );
        assert!(
            !destination.starts_with(env!("CARGO_MANIFEST_DIR")),
            "staged executable stays outside the checkout"
        );
        assert_eq!(
            fs::read(&destination).expect("read staged bytes"),
            fs::read(area.binary()).expect("read Cargo artifact bytes"),
            "staged executable preserves the exact Cargo artifact bytes"
        );
        assert_ne!(
            staged_meta.permissions().mode() & 0o111,
            0,
            "staged executable keeps an owner-executable mode"
        );
        assert!(
            !parent_holds_writable_fd_for(&destination),
            "harness parent holds no writable descriptor for the staged inode"
        );
        let help = Command::new(&destination)
            .arg("--help")
            .env("RUSTSCRIPT_AGENT_HOME", "")
            .env("HOME", area.root.join("isolated-default-home"))
            .env_remove("USERPROFILE")
            .current_dir(&area.caller)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run staged copy --help");
        assert_eq!(
            help.status.code(),
            Some(0),
            "staged copy --help stderr={}",
            String::from_utf8_lossy(&help.stderr)
        );
        area.root.clone()
    };
    assert!(!root.exists(), "private staging area is cleaned up");
}
