use rustscript_agent::{
    RunCancellation,
    auth::host::{AuthHost, auth_host_catalog},
    config_file::ConfigFile,
};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmStatus,
    compile_source_at_path_with_flavor_and_options,
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

struct TempHome(PathBuf);

impl TempHome {
    fn new(label: &str) -> Self {
        let root =
            PathBuf::from(std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned temp"));
        let path = root.join(format!("oauth-config-{label}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).expect("create assigned temporary home");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("private home mode");
        Self(path)
    }

    fn write_config(&self, contents: &str) {
        let path = self.0.join("config.yaml");
        fs::write(&path, contents).expect("write temporary config");
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("config file mode");
    }

    fn write_empty_auth(&self) {
        let path = self.0.join("auth.yaml");
        fs::write(&path, "version: 1\ncredentials: {}\n").expect("write temporary auth file");
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("auth file mode");
    }
}

impl AsRef<Path> for TempHome {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn config_with_oauth_fields(fields: &str) -> String {
    format!(
        "version: 1\nproviders:\n  public-test:\n    protocol: fixture\n    base_url: https://example.test/api\n    oauth:\n{fields}"
    )
}

fn load_config(fields: &str, label: &str) -> serde_json::Value {
    let loaded = load_config_result(fields, label).expect("real config loader");
    serde_json::to_value(loaded).expect("canonical config serialization")
}

fn load_config_result(
    fields: &str,
    label: &str,
) -> Result<ConfigFile, rustscript_agent::config_file::ConfigFileError> {
    let home = TempHome::new(label);
    home.write_config(&config_with_oauth_fields(fields));
    ConfigFile::load(home.0.join("config.yaml"))
}

fn fields_with_scopes(scopes: &[String]) -> String {
    format!(
        "      flow: fixture\n      scopes: {}\n",
        serde_json::to_string(scopes).expect("JSON-compatible YAML sequence")
    )
}

fn fields_with_parameters(parameters: &[(String, String)]) -> String {
    let entries: Vec<_> = parameters
        .iter()
        .map(|(name, value)| serde_json::json!({"name": name, "value": value}))
        .collect();
    format!(
        "      flow: fixture\n      authorization_parameters: {}\n",
        serde_json::to_string(&entries).expect("JSON-compatible YAML sequence")
    )
}

fn assert_static_invalid(fields: &str, label: &str, forbidden: &[&str]) {
    let home = TempHome::new(label);
    home.write_config(&config_with_oauth_fields(fields));
    home.write_empty_auth();
    let config_path = home.0.join("config.yaml");
    let auth_path = home.0.join("auth.yaml");
    let before_config = fs::read(&config_path).expect("config bytes before rejected load");
    let before_auth = fs::read(&auth_path).expect("auth bytes before rejected load");
    let mut before_entries: Vec<_> = fs::read_dir(&home.0)
        .expect("directory before rejected load")
        .map(|entry| entry.expect("directory entry").file_name())
        .collect();
    before_entries.sort();

    let error = match ConfigFile::load(&config_path) {
        Err(error) => error,
        Ok(_) => panic!("loader accepted invalid OAuth public config"),
    };
    assert!(
        matches!(
            error,
            rustscript_agent::config_file::ConfigFileError::InvalidValue { .. }
        ),
        "expected a static field validation error, got {error:?}"
    );
    let rendered = error.to_string();
    for secret in forbidden {
        assert!(
            !rendered.contains(secret),
            "loader reflected supplied input {secret:?}: {rendered}"
        );
    }

    assert_eq!(
        fs::read(&config_path).expect("config bytes after rejection"),
        before_config
    );
    assert_eq!(
        fs::read(&auth_path).expect("auth bytes after rejection"),
        before_auth
    );
    let mut after_entries: Vec<_> = fs::read_dir(&home.0)
        .expect("directory after rejected load")
        .map(|entry| entry.expect("directory entry").file_name())
        .collect();
    after_entries.sort();
    assert_eq!(after_entries, before_entries);
}

#[test]
fn real_config_loader_accepts_and_preserves_configured_oauth_values() {
    let home = TempHome::new("loader-valid");
    home.write_config(&config_with_oauth_fields(
        "      scopes:\n        - profile.read\n        - profile.read\n        - openid email\n        - 'μ-scope'\n      authorization_parameters:\n        - name: audience\n          value: 'api v2+blue&kind=public 東京'\n        - name: prompt.mode\n          value: consent\n",
    ));

    let loaded = ConfigFile::load(home.0.join("config.yaml"))
        .expect("the real config loader must accept bounded configured OAuth values");
    let snapshot = serde_json::to_value(loaded).expect("serialize canonical typed config");
    let oauth = &snapshot["providers"]["public-test"]["oauth"];
    assert_eq!(
        oauth["scopes"],
        serde_json::json!(["profile.read", "profile.read", "openid email", "μ-scope"])
    );
    assert_eq!(
        oauth["authorization_parameters"],
        serde_json::json!([
            {"name": "audience", "value": "api v2+blue&kind=public 東京"},
            {"name": "prompt.mode", "value": "consent"}
        ])
    );
}

#[test]
fn real_config_loader_distinguishes_absent_from_explicit_empty_options() {
    let absent = load_config("      flow: fixture\n", "loader-absent");
    let empty = load_config(
        "      flow: fixture\n      scopes: []\n      authorization_parameters: []\n",
        "loader-empty",
    );
    let absent_oauth = &absent["providers"]["public-test"]["oauth"];
    let empty_oauth = &empty["providers"]["public-test"]["oauth"];
    assert_eq!(absent_oauth.get("scopes"), Some(&serde_json::Value::Null));
    assert_eq!(
        absent_oauth.get("authorization_parameters"),
        Some(&serde_json::Value::Null)
    );
    assert_eq!(empty_oauth["scopes"], serde_json::json!([]));
    assert_eq!(
        empty_oauth["authorization_parameters"],
        serde_json::json!([])
    );
}

#[test]
fn loader_accepts_scope_and_parameter_limits_at_exact_boundaries() {
    let scopes = vec!["s".repeat(2048 / 32); 32];
    let scope_fields = fields_with_scopes(&scopes);
    assert!(load_config_result(&scope_fields, "scope-boundary").is_ok());

    let mut parameters: Vec<(String, String)> = (0..32)
        .map(|index| (format!("p{index}"), String::new()))
        .collect();
    let name_bytes: usize = parameters.iter().map(|(name, _)| name.len()).sum();
    parameters[0].1 = "v".repeat(2048usize.saturating_sub(name_bytes));
    let parameter_fields = fields_with_parameters(&parameters);
    assert!(load_config_result(&parameter_fields, "parameter-boundary").is_ok());
}

#[test]
fn loader_rejects_scope_bounds_and_controls_without_reflection() {
    assert_static_invalid(&fields_with_scopes(&[String::new()]), "scope-empty", &[]);

    let control_scope = format!("scope-{}SCOPE_MARKER", '\u{1}');
    assert_static_invalid(
        &fields_with_scopes(&[control_scope]),
        "scope-control",
        &["SCOPE_MARKER"],
    );

    let too_many: Vec<String> = (0..33).map(|index| format!("scope-{index}")).collect();
    assert_static_invalid(&fields_with_scopes(&too_many), "scope-count", &["scope-0"]);

    let too_many_bytes = vec!["SCOPE_AGGREGATE_MARKER".to_string(), "x".repeat(2048)];
    assert_static_invalid(
        &fields_with_scopes(&too_many_bytes),
        "scope-bytes",
        &["SCOPE_AGGREGATE_MARKER"],
    );
}

#[test]
fn loader_rejects_query_bounds_names_collisions_controls_and_unknown_fields() {
    assert_static_invalid(
        &fields_with_parameters(&[(String::new(), "EMPTY_NAME_MARKER".to_string())]),
        "parameter-empty-name",
        &["EMPTY_NAME_MARKER"],
    );
    assert_static_invalid(
        &fields_with_parameters(&[("audience:region".into(), "INVALID_NAME_MARKER".into())]),
        "parameter-invalid-name",
        &["INVALID_NAME_MARKER", "\"audience:region\""],
    );
    assert_static_invalid(
        &fields_with_parameters(&[("audience".into(), "VALUE_CONTROL_MARKER\u{1}".into())]),
        "parameter-control",
        &["VALUE_CONTROL_MARKER"],
    );
    assert_static_invalid(
        &fields_with_parameters(&[
            ("duplicate".into(), "DUPLICATE_ONE_MARKER".into()),
            ("duplicate".into(), "DUPLICATE_TWO_MARKER".into()),
        ]),
        "parameter-duplicate",
        &[
            "DUPLICATE_ONE_MARKER",
            "DUPLICATE_TWO_MARKER",
            "\"duplicate\"",
        ],
    );

    let reserved = [
        "host",
        "authorization",
        "cookie",
        "redirect_uri",
        "code_verifier",
        "verifier",
        "state",
        "code_challenge",
        "code_challenge_method",
        "url",
        "authority",
        "code",
        "authorization_code",
        "device_auth_id",
        "device_code",
        "access_token",
        "refresh_token",
        "id_token",
        "token",
        "api_key",
        "client_secret",
        "password",
        "secret",
        "scope",
        "client_id",
        "response_type",
    ];
    for name in reserved {
        let fields =
            fields_with_parameters(&[(name.to_ascii_uppercase(), "RESERVED_VALUE_MARKER".into())]);
        assert_static_invalid(
            &fields,
            "parameter-reserved",
            &[
                "RESERVED_VALUE_MARKER",
                &format!("\"{}\"", name.to_ascii_uppercase()),
            ],
        );
    }

    let too_many: Vec<(String, String)> = (0..33)
        .map(|index| (format!("p{index}"), format!("PARAM_COUNT_MARKER_{index}")))
        .collect();
    assert_static_invalid(
        &fields_with_parameters(&too_many),
        "parameter-count",
        &["PARAM_COUNT_MARKER_0"],
    );

    let too_many_bytes = vec![(
        "audience".into(),
        "PARAM_BYTES_MARKER".to_string() + &"x".repeat(2048),
    )];
    assert_static_invalid(
        &fields_with_parameters(&too_many_bytes),
        "parameter-bytes",
        &["PARAM_BYTES_MARKER"],
    );

    assert_static_invalid(
        "      flow: fixture\n      authorization_parameters: [{\"name\":\"audience\",\"value\":\"ok\",\"extra\":\"UNKNOWN_FIELD_MARKER\"}]\n",
        "parameter-unknown-field",
        &["UNKNOWN_FIELD_MARKER"],
    );

    let case_sensitive = vec![
        ("Audience".into(), String::new()),
        ("audience".into(), "distinct case".into()),
    ];
    assert!(
        load_config_result(
            &fields_with_parameters(&case_sensitive),
            "parameter-case-sensitive"
        )
        .is_ok()
    );
}

const TYPED_RSS: &str = r#"
use config;

struct OAuthConfigProjection {
    scopes: array<string>?,
    authorization_parameters: array<PublicQueryEntry>?,
    first_parameter_name: string?,
    first_parameter_value: string?
}

pub fn read_config(home: resource<auth.host_home>) -> OAuthConfigProjection {
    let snapshot: ConfigSnapshotEnvelope = config::load_snapshot(&home);
    let public_config: BoundedPublicConfig = snapshot.public_config;
    let providers: array<ProviderEntry> = public_config.providers;
    let provider: ProviderEntry = providers[0].copy();
    let mut scopes: array<string>? = null;
    let mut parameters: array<PublicQueryEntry>? = null;
    if provider.oauth.copy() != null {
        let oauth: OAuthConfig = provider.oauth.copy();
        scopes = oauth.scopes;
        parameters = oauth.authorization_parameters;
    }
    let mut first_name: string? = null;
    let mut first_value: string? = null;
    if parameters != null {
        let present_parameters: array<PublicQueryEntry> = parameters;
        if present_parameters.length > 0 {
            let first: PublicQueryEntry = present_parameters[0].copy();
            first_name = first.name;
            first_value = first.value;
        }
    }
    {
        scopes: scopes,
        authorization_parameters: parameters,
        first_parameter_name: first_name,
        first_parameter_value: first_value
    }
}
"#;

fn compile_typed_rss() -> Vm {
    let source_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_auth_rss/config.yaml");
    let compiled = compile_source_at_path_with_flavor_and_options(
        &source_path,
        TYPED_RSS,
        SourceFlavor::RustScript,
        CompileSourceFileOptions::default().with_host_api_catalog(auth_host_catalog()),
    )
    .expect("typed RSS must compile against the canonical auth host catalog");
    let mut vm = Vm::new_shared(Arc::new(compiled.program));
    let mut registry = HostFunctionRegistry::restricted();
    let registration_home = TempHome::new("registration");
    registration_home.write_config(&config_with_oauth_fields("      scopes: []\n"));
    registration_home.write_empty_auth();
    AuthHost::new(
        registration_home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("registration host")
    .register(&mut registry, auth_host_catalog().as_ref())
    .expect("register exact auth catalog");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind only registered functions");
    assert!(matches!(vm.run().expect("RSS root"), VmStatus::Halted));
    vm
}

fn optional_value_field(value: &Value, name: &str) -> Option<Value> {
    let Value::Map(entries) = value else {
        panic!("expected named RSS value, got {value:?}");
    };
    entries.iter().find_map(|(key, value)| {
        matches!(key, Value::String(key) if key.as_ref() == name).then(|| value.clone())
    })
}

fn value_field(value: &Value, name: &str) -> Value {
    optional_value_field(value, name)
        .unwrap_or_else(|| panic!("missing RSS field {name}: {value:?}"))
}

fn invoke_projection(vm: &mut Vm, home: &AuthHost) -> Value {
    let context = home.bind_vm(vm).expect("bind genuine host home");
    let host_home = value_field(&context, "host_home");
    let callable = vm
        .resolve_exported_callable("read_config")
        .expect("RSS export");
    vm.invoke_callable(callable, &[host_home])
        .expect("typed RSS config projection")
}

fn project_typed_fields(fields: &str, label: &str) -> Value {
    let mut vm = compile_typed_rss();
    let home = TempHome::new(label);
    home.write_config(&config_with_oauth_fields(fields));
    home.write_empty_auth();
    let before_config = fs::read(home.0.join("config.yaml")).expect("config before projection");
    let before_auth = fs::read(home.0.join("auth.yaml")).expect("auth before projection");
    let host = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("real host from configured home");
    let projected = invoke_projection(&mut vm, &host);
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config after projection"),
        before_config
    );
    assert_eq!(
        fs::read(home.0.join("auth.yaml")).expect("auth after projection"),
        before_auth
    );
    assert_eq!(vm.host_context().resource_count(), 2);
    projected
}

#[test]
fn real_auth_host_snapshot_projects_absent_and_explicit_empty_options() {
    let absent = project_typed_fields("      flow: fixture\n", "typed-absent");
    assert_eq!(optional_value_field(&absent, "scopes"), None);
    assert_eq!(
        optional_value_field(&absent, "authorization_parameters"),
        None
    );
    assert_eq!(optional_value_field(&absent, "first_parameter_name"), None);
    assert_eq!(optional_value_field(&absent, "first_parameter_value"), None);

    let empty = project_typed_fields(
        "      flow: fixture\n      scopes: []\n      authorization_parameters: []\n",
        "typed-empty",
    );
    assert_eq!(
        optional_value_field(&empty, "scopes"),
        Some(Value::array(vec![]))
    );
    assert_eq!(
        optional_value_field(&empty, "authorization_parameters"),
        Some(Value::array(vec![]))
    );
    assert_eq!(optional_value_field(&empty, "first_parameter_name"), None);
    assert_eq!(optional_value_field(&empty, "first_parameter_value"), None);
}

#[test]
fn real_auth_host_snapshot_is_read_through_typed_restricted_rss() {
    let mut vm = compile_typed_rss();
    let home = TempHome::new("typed-projection");
    home.write_config(&config_with_oauth_fields(
        "      scopes:\n        - scope:first\n        - 'scope with space'\n        - '東京'\n      authorization_parameters:\n        - name: audience\n          value: 'value with space+plus&ampersand&東京'\n",
    ));
    home.write_empty_auth();
    let before_config = fs::read(home.0.join("config.yaml")).expect("config bytes before call");
    let before_auth = fs::read(home.0.join("auth.yaml")).expect("auth bytes before call");
    let host = AuthHost::new(
        home.0.clone(),
        RunCancellation::with_timeout(Duration::from_secs(30)),
    )
    .expect("real host from configured home");

    let projected = invoke_projection(&mut vm, &host);
    assert_eq!(
        value_field(&projected, "scopes"),
        Value::array(vec![
            Value::string("scope:first"),
            Value::string("scope with space"),
            Value::string("東京"),
        ])
    );
    let parameters = value_field(&projected, "authorization_parameters");
    let Value::Array(entries) = parameters else {
        panic!("expected typed PublicQueryEntry array, got {parameters:?}");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(value_field(&entries[0], "name"), Value::string("audience"));
    assert_eq!(
        value_field(&entries[0], "value"),
        Value::string("value with space+plus&ampersand&東京")
    );
    assert_eq!(
        value_field(&projected, "first_parameter_name"),
        Value::string("audience")
    );
    assert_eq!(
        value_field(&projected, "first_parameter_value"),
        Value::string("value with space+plus&ampersand&東京")
    );
    assert_eq!(
        fs::read(home.0.join("config.yaml")).expect("config after call"),
        before_config
    );
    assert_eq!(
        fs::read(home.0.join("auth.yaml")).expect("auth after call"),
        before_auth
    );
    assert_eq!(vm.host_context().resource_count(), 2);
}
