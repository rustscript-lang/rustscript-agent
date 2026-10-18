//! Native-auth fixture for the migrated provider regression suites.
//!
//! Each test builds a private fixture home whose trusted config owns one
//! HTTPS authority plus base path, injects a counted public
//! `BoundedHttpsTransport` through `OAuthHost`, and drives the production
//! `rss/llm/harness.rss` entry with an `AuthHostFactory`. No live network,
//! no raw credentials in requests, profiles, or options, and no ambient raw
//! HTTP: the harness runner uses `AgentConfig::default()`.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustscript_agent::auth::{
    host::AuthHost,
    oauth::{
        BoundedHttpsTransport, OAuthHost, ScriptedBrowser, ScriptedCallback, ScriptedCancel,
        ScriptedClock,
    },
};
use rustscript_agent::{AgentConfig, AgentHostBridges, AgentRunner, RunCancellation};
use rustscript_vm::Value;
use serde_json::{Value as JsonValue, json};

/// Private fixture home whose trusted config admits one synthetic provider.
pub struct FixtureHome {
    path: PathBuf,
}

impl FixtureHome {
    /// Writes `config.yaml`/`auth.yaml` trusting `base_url` for `provider`
    /// under `credential`, with `access` as the stored synthetic token. All
    /// OAuth endpoints stay on the trusted base authority so the admitted
    /// policy holds exactly one authority.
    pub fn for_profile(
        label: &str,
        provider: &str,
        base_url: &str,
        credential: &str,
        access: &str,
    ) -> Self {
        let root = PathBuf::from(
            std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned fixture temp"),
        );
        let home = root.join(format!("provider-opaque-{label}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&home).expect("create private fixture home");
        let authority = base_url
            .strip_prefix("https://")
            .and_then(|rest| rest.split('/').next())
            .expect("trusted base is an https authority URL");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_auth_rss");
        let config = fs::read_to_string(fixture.join("config.yaml"))
            .expect("read config fixture")
            .replace("openai-codex", provider)
            .replace("https://chatgpt.com/backend-api/codex", base_url)
            .replace("fixture-codex", credential)
            .replace("https://auth.openai.com", &format!("https://{authority}"));
        fs::write(home.join("config.yaml"), config).expect("write private config fixture");
        let auth = fs::read_to_string(fixture.join("auth.yaml"))
            .expect("read auth fixture")
            .replace("1788440000000", "1900003600000")
            .replace("openai-codex", provider)
            .replace("fixture-codex", credential)
            .replace("SYNTHETIC_ACCESS_TOKEN", access);
        fs::write(home.join("auth.yaml"), auth).expect("write private auth fixture");
        #[cfg(unix)]
        {
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
            for name in ["config.yaml", "auth.yaml"] {
                fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600))
                    .expect("fixture file mode");
            }
        }
        Self { path: home }
    }

    /// Fixture-only expiry override for actual refresh decisions.
    pub fn with_expiry(self, credential: &str, expires_at_ms: i64) -> Self {
        let path = self.path.join("auth.yaml");
        let mut auth: serde_yaml::Value =
            serde_yaml::from_str(&fs::read_to_string(&path).expect("auth fixture"))
                .expect("auth fixture YAML");
        auth["credentials"][credential]["expires_at_ms"] =
            serde_yaml::Value::Number(expires_at_ms.into());
        fs::write(
            &path,
            serde_yaml::to_string(&auth).expect("auth fixture YAML"),
        )
        .expect("write fixture expiry");
        self
    }

    /// Trusted test-side persistence readback; never supplied to a guest.
    pub fn stored_auth(&self) -> serde_yaml::Value {
        serde_yaml::from_str(
            &fs::read_to_string(self.path.join("auth.yaml")).expect("stored auth fixture"),
        )
        .expect("stored auth YAML")
    }

    fn update_auth(&self, update: impl FnOnce(&mut serde_yaml::Value)) {
        let path = self.path.join("auth.yaml");
        let mut document = self.stored_auth();
        update(&mut document);
        fs::write(path, serde_yaml::to_string(&document).expect("auth YAML"))
            .expect("write synthetic credential fixture");
    }

    pub fn without_refresh_token(self, credential: &str) -> Self {
        self.update_auth(|document| {
            document["credentials"][credential]
                .as_mapping_mut()
                .expect("credential")
                .remove(serde_yaml::Value::String("refresh_token".to_string()));
        });
        self
    }

    pub fn with_api_key(self, credential: &str) -> Self {
        self.update_auth(|document| {
            document["credentials"][credential]["kind"] =
                serde_yaml::Value::String("api_key".to_string());
        });
        self.without_refresh_token(credential)
    }

    pub fn without_oauth_configuration(self, provider: &str) -> Self {
        let path = self.path.join("config.yaml");
        let mut config: serde_yaml::Value =
            serde_yaml::from_str(&fs::read_to_string(&path).expect("config fixture"))
                .expect("config YAML");
        config["providers"][provider]
            .as_mapping_mut()
            .expect("provider")
            .remove(serde_yaml::Value::String("oauth".to_string()));
        fs::write(path, serde_yaml::to_string(&config).expect("config YAML"))
            .expect("write trusted fixture without OAuth configuration");
        self
    }

    pub fn with_refresh_skew_seconds(self, provider: &str, seconds: i64) -> Self {
        let path = self.path.join("config.yaml");
        let mut config: serde_yaml::Value =
            serde_yaml::from_str(&fs::read_to_string(&path).expect("config fixture"))
                .expect("config YAML");
        config["providers"][provider]["oauth"]["refresh_skew_seconds"] =
            serde_yaml::Value::Number(seconds.into());
        fs::write(path, serde_yaml::to_string(&config).expect("config YAML"))
            .expect("write trusted fixture refresh skew");
        self
    }

    pub fn auth_factory<T: BoundedHttpsTransport + 'static>(
        &self,
        transport: Arc<T>,
    ) -> Arc<dyn Fn(RunCancellation) -> Result<AuthHost, String> + Send + Sync> {
        let oauth = Arc::new(OAuthHost::new(
            transport,
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::new(ScriptedClock::new(1_900_000_000_000)),
            Arc::new(ScriptedCancel::new()),
        ));
        let home_path = self.path.clone();
        Arc::new(move |cancellation: RunCancellation| {
            AuthHost::new(home_path.clone(), cancellation)
                .map(|host| host.with_oauth_host(Arc::clone(&oauth)))
        })
    }
}

impl Drop for FixtureHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Production harness runner with native auth, the default (deny-by-default)
/// ambient transport policy, and a finite run deadline.
pub fn harness_runner<T: BoundedHttpsTransport + 'static>(
    home: &FixtureHome,
    transport: Arc<T>,
) -> AgentRunner {
    let bridges = AgentHostBridges {
        auth_host_factory: Some(home.auth_factory(transport)),
        ..AgentHostBridges::default()
    };
    AgentRunner::from_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/llm/harness.rss"),
        AgentConfig::default(),
    )
    .expect("production provider harness should compile")
    .with_host(bridges)
    .with_cancellation(RunCancellation::with_timeout(Duration::from_secs(30)))
}

/// Production harness runner sharing one scripted clock, so expiry during a
/// live stream is deterministic (no sleeps, no threads).
pub fn harness_runner_with_clock<T: BoundedHttpsTransport + 'static>(
    home: &FixtureHome,
    transport: Arc<T>,
    clock: Arc<ScriptedClock>,
) -> AgentRunner {
    let oauth = Arc::new(OAuthHost::new(
        transport,
        Arc::new(ScriptedCallback::new()),
        Arc::new(ScriptedBrowser::new()),
        clock,
        Arc::new(ScriptedCancel::new()),
    ));
    let home_path = home.path.clone();
    let factory = Arc::new(move |cancellation: RunCancellation| {
        AuthHost::new(home_path.clone(), cancellation)
            .map(|host| host.with_oauth_host(Arc::clone(&oauth)))
    });
    let bridges = AgentHostBridges {
        auth_host_factory: Some(factory),
        ..AgentHostBridges::default()
    };
    AgentRunner::from_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/llm/harness.rss"),
        AgentConfig::default(),
    )
    .expect("production provider harness should compile")
    .with_host(bridges)
    .with_cancellation(RunCancellation::with_timeout(Duration::from_secs(30)))
}

/// Production harness runner with a caller-supplied finite deadline. A
/// pre-cancelled deadline fails before any native send.
pub fn harness_runner_with_cancellation<T: BoundedHttpsTransport + 'static>(
    home: &FixtureHome,
    transport: Arc<T>,
    cancellation: RunCancellation,
) -> AgentRunner {
    let bridges = AgentHostBridges {
        auth_host_factory: Some(home.auth_factory(transport)),
        ..AgentHostBridges::default()
    };
    AgentRunner::from_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/llm/harness.rss"),
        AgentConfig::default(),
    )
    .expect("production provider harness should compile")
    .with_host(bridges)
    .with_cancellation(cancellation)
}

/// Root context for one harness invocation: the named credential travels as a
/// top-level public reference, never as embedded secret material.
pub fn harness_context(
    kind: &str,
    request: JsonValue,
    profile: JsonValue,
    credential_id: &str,
) -> Value {
    Value::map(vec![
        (Value::string("kind"), Value::string(kind)),
        (Value::string("request"), json_to_vm_value(&request)),
        (Value::string("profile"), json_to_vm_value(&profile)),
        (Value::string("credential_id"), Value::string(credential_id)),
    ])
}

/// Reads one provider transcript fixture.
pub fn read_provider_fixture(relative: &str) -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/providers")
            .join(relative),
    )
    .unwrap_or_else(|error| panic!("fixture {relative} should be readable: {error}"))
}

/// Splits one `.sse` transcript into one event string per dispatch.
pub fn sse_events(transcript: &str) -> Vec<String> {
    transcript
        .split("\n\n")
        .map(str::trim_end)
        .filter(|event| !event.is_empty())
        .map(|event| format!("{event}\n\n"))
        .collect()
}

/// Canonical public chat request: model/messages/tools/sampling only, with an
/// empty public provider-options map and no secret-shaped entries.
pub fn canonical_request(stream: bool) -> JsonValue {
    let mut request: JsonValue =
        serde_json::from_str(&read_provider_fixture("requests/chat_request.json"))
            .expect("canonical request fixture should be JSON");
    request["provider_options"] = json!({});
    request["stream"] = json!(stream);
    request
}

pub fn json_to_vm_value(value: &JsonValue) -> Value {
    match value {
        JsonValue::Null => Value::Null,
        JsonValue::Bool(value) => Value::Bool(*value),
        JsonValue::Number(value) => {
            if let Some(value) = value.as_i64() {
                Value::Int(value)
            } else {
                Value::Float(value.as_f64().expect("finite JSON number"))
            }
        }
        JsonValue::String(value) => Value::string(value),
        JsonValue::Array(values) => Value::Array(Arc::new(
            values.iter().map(json_to_vm_value).collect::<Vec<_>>(),
        )),
        JsonValue::Object(entries) => Value::map(
            entries
                .iter()
                .map(|(key, value)| (Value::string(key), json_to_vm_value(value)))
                .collect(),
        ),
    }
}

/// Converts one VM value into JSON (test-side mirror of the gateway renderer).
pub fn vm_value_to_json(value: &Value) -> JsonValue {
    match value {
        Value::Null => JsonValue::Null,
        Value::Int(value) => json!(value),
        Value::Float(value) => serde_json::Number::from_f64(*value)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        Value::Bool(value) => json!(value),
        Value::String(value) => JsonValue::String(value.to_string()),
        Value::Bytes(value) => JsonValue::String(String::from_utf8_lossy(value).into_owned()),
        Value::Array(values) => JsonValue::Array(values.iter().map(vm_value_to_json).collect()),
        Value::Map(entries) => JsonValue::Object(
            entries
                .iter()
                .filter_map(|(key, value)| match key {
                    Value::String(key) => Some((key.to_string(), vm_value_to_json(value))),
                    _ => None,
                })
                .collect(),
        ),
        Value::Callable(_) => JsonValue::String("<callable>".to_string()),
    }
}
