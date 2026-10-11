//! Source-grounded packaged setup/migration documentation guards.
//!
//! These tests keep the *packaged* setup surface truthful against the current
//! immutable BASE source. They are deliberately independent of the A9
//! `docs_consistency_tests.rs` env/field scanner and only assert claims that
//! are decided by concrete artifacts in this revision:
//!
//! - the pinned core revision and the `[[bin]]` set are derived from
//!   `Cargo.toml` / `Cargo.lock`, not hard-coded in the docs;
//! - `docs/configuration.md` documents the authoritative RSS agent-source
//!   selection contract (`RUSTSCRIPT_AGENT_SOURCE` / legacy
//!   `RUSTSCRIPT_AGENT_SCRIPT`), whose precedence, validation, and migration
//!   semantics are owned by `rss/agent/source_policy.rss`;
//! - the production auth host module really registers `config::load_snapshot`,
//!   so the docs must not claim the production bridge is absent;
//! - the shipped `docs/examples/*.yaml` decode through the real bounded
//!   `ConfigFile` / `AuthConfig` loaders and the real RSS source-selection
//!   entry — no fabricated protocol hosts, no live home access.
//!
//! Every expected token is read from source at test time so a source change
//! fails here instead of silently drifting.

use std::path::PathBuf;
use std::sync::Arc;

use rustscript_agent::{AuthConfig, ConfigFile};
use rustscript_vm::{
    CompileSourceFileOptions, HostFunctionRegistry, InvocationItem, InvocationPoll, SourceFlavor,
    Value, Vm, VmStatus, catalog_named_struct_schemas, compile_source_with_flavor_and_options,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_relative(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("read {path}: {error}"))
}

/// The full 40-character revision pinned for the core Git dependency in
/// `Cargo.toml` (`rustscript-vm = { … rev = "<sha>" … }`).
fn manifest_core_revision() -> String {
    let manifest = read_relative("Cargo.toml");
    let line = manifest
        .lines()
        .find(|line| line.trim_start().starts_with("rustscript-vm = {"))
        .expect("Cargo.toml must declare the rustscript-vm dependency");
    let rev = line
        .split("rev = \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("rustscript-vm must pin a rev");
    assert_eq!(
        rev.len(),
        40,
        "the pinned core rev must be the full SHA: {rev}"
    );
    rev.to_string()
}

/// Every `[package] name` declared under a `[[bin]]` section.
fn manifest_binary_names() -> Vec<String> {
    let manifest = read_relative("Cargo.toml");
    let mut names = Vec::new();
    for block in manifest.split("[[bin]]").skip(1) {
        let name = block
            .lines()
            .find_map(|line| line.trim().strip_prefix("name = \""))
            .and_then(|rest| rest.split('"').next())
            .expect("[[bin]] block must declare a name");
        names.push(name.to_string());
    }
    assert!(
        !names.is_empty(),
        "Cargo.toml must declare at least one binary"
    );
    names
}

#[test]
fn deployment_documents_the_manifest_pinned_core_revision() {
    let rev = manifest_core_revision();
    let deployment = read_relative("docs/deployment.md");
    assert!(
        deployment.contains(&rev),
        "docs/deployment.md must quote the core revision pinned in Cargo.toml ({rev})"
    );
    // The lockfile records the canonical git source at the same full rev.
    let lock = read_relative("Cargo.lock");
    let canonical =
        format!("git+https://github.com/rustscript-lang/rustscript.git?rev={rev}#{rev}");
    assert!(
        lock.contains(&canonical),
        "Cargo.lock must resolve the core to the canonical HTTPS source at {rev}"
    );
    // The stale revision this guide previously quoted must never return.
    assert!(
        !deployment.contains("fd4b570d08d7cc90cc29e3b05df59c9e9bf3b88e"),
        "docs/deployment.md still quotes the stale core revision fd4b570d…"
    );
}

#[test]
fn deployment_documents_exactly_the_manifest_binary_set() {
    let bins = manifest_binary_names();
    let deployment = read_relative("docs/deployment.md");
    for bin in &bins {
        assert!(
            deployment.contains(bin.as_str()),
            "docs/deployment.md must name the manifest binary `{bin}`"
        );
        assert!(
            deployment.contains(&format!("target/release/{bin}")),
            "docs/deployment.md must name the release artifact target/release/{bin}"
        );
    }
    // The guide must not advertise a release artifact that is not built.
    for invented in ["rustscript-agent-cli", "rustscript-agent-daemon"] {
        assert!(
            !deployment.contains(invented),
            "docs/deployment.md must not invent an unbuilt binary `{invented}`"
        );
    }
}

fn gateway_startup_example<'a>(document: &'a str, path: &str) -> &'a str {
    document
        .split("```bash")
        .skip(1)
        .filter_map(|fenced| fenced.split_once("```").map(|(example, _)| example))
        .find(|example| {
            example
                .lines()
                .any(|line| line.trim() == "cargo run --release --bin rustscript-agent-gateway")
        })
        .unwrap_or_else(|| panic!("{path} must include its gateway startup bash example"))
}

#[test]
fn gateway_startup_examples_use_admitted_bundled_coding_source() {
    for (path, document) in [
        ("README.md", read_relative("README.md")),
        (
            "docs/configuration.md",
            read_relative("docs/configuration.md"),
        ),
    ] {
        let example = gateway_startup_example(&document, path);
        assert!(
            example.lines().any(|line| {
                line.trim_end_matches('\\').trim() == "RUSTSCRIPT_AGENT_SOURCE=bundled:coding"
            }),
            "{path} gateway startup example must select the admitted bundled coding source"
        );
        assert!(
            !example
                .lines()
                .any(|line| line.trim_start().starts_with("RUSTSCRIPT_AGENT_SCRIPT=")),
            "{path} gateway startup example must not use the rejected relative legacy script"
        );
    }
}

#[test]
fn gateway_home_documentation_matches_workspace_host_contract() {
    let gateway = read_relative("src/bin/rustscript-agent-gateway.rs");
    assert!(gateway.contains("var_os(\"RUSTSCRIPT_AGENT_HOME\")"));
    assert!(gateway.contains("state.with_workspace_home(home)"));
    let gateway_module = read_relative("src/gateway/mod.rs");
    assert!(gateway_module.contains("set_workspace_host_factory"));
    assert!(gateway_module.contains("AuthHost::new(home.clone(), cancellation)"));
    let config_paths = read_relative("src/config_file.rs");
    assert!(config_paths.contains("home.join(STATE_FILE_NAME)"));
    assert!(config_paths.contains("home.is_relative()"));
    assert!(config_paths.contains("Component::ParentDir"));

    let configuration = read_relative("docs/configuration.md");
    let source_start = configuration
        .find("## Configuration sources")
        .expect("configuration.md must document its source table");
    let source_rest = &configuration[source_start..];
    let source_end = source_rest
        .find("\n## ")
        .expect("configuration source section must end before the next section");
    let source_section = &source_rest[..source_end];
    assert!(
        source_section.contains("workspace host"),
        "the source table must include the gateway's workspace-host HOME use"
    );
    assert!(
        !source_section.contains("library-only `RUSTSCRIPT_AGENT_HOME`"),
        "the source table must not classify HOME as library-only"
    );
    let start = configuration
        .find("### Agent home (library bootstrap and gateway workspace host)")
        .expect("configuration.md must retain the HOME section");
    let rest = &configuration[start..];
    let end = rest
        .find("\n### Gateway variables")
        .expect("HOME section must end before gateway variables");
    let home_section = &rest[..end];
    assert!(
        home_section.contains("workspace host"),
        "HOME docs must describe the gateway's workspace-host use"
    );
    assert!(
        !home_section.contains("It is not consumed by the current gateway binary"),
        "HOME docs must not claim the gateway ignores RUSTSCRIPT_AGENT_HOME"
    );
    assert!(
        home_section.contains("absolute") && home_section.contains("parent-directory"),
        "HOME docs must retain source-backed path validation"
    );
    assert!(
        home_section.contains("RUSTSCRIPT_AGENT_STATE_DB"),
        "HOME docs must distinguish the SQLite path selector"
    );
}

#[test]
fn auth_storage_documentation_matches_secret_and_unix_file_contract() {
    let auth_config = read_relative("src/auth/config.rs");
    assert!(auth_config.contains("pub(crate) access_token: SecretText"));
    assert!(auth_config.contains("pub(crate) refresh_token: Option<SecretText>"));
    assert!(auth_config.contains("has_refresh_token: self.refresh_token.is_some()"));
    let auth_store = read_relative("src/auth/store.rs");
    for required in [
        "stat.st_nlink != 1",
        "stat.st_uid != unsafe { libc::geteuid() }",
        "mode != 0o600",
        "libc::S_IFREG",
    ] {
        assert!(
            auth_store.contains(required),
            "AuthStore must retain the Unix file guard `{required}`"
        );
    }

    let configuration = read_relative("docs/configuration.md");
    for required in [
        "secret slots",
        "access",
        "refresh",
        "sanitized",
        "opaque",
        "has_refresh_token",
    ] {
        assert!(
            configuration.contains(required),
            "configuration docs must distinguish stored secrets from public metadata (`{required}`)"
        );
    }
    assert!(
        !configuration.contains("the two secrets in this revision"),
        "configuration docs must include provider credentials stored in auth.yaml"
    );

    let deployment = read_relative("docs/deployment.md");
    for required in [
        "auth.yaml",
        "offline",
        "regular file",
        "exactly one link",
        "effective user",
        "0600",
        "rotation",
    ] {
        assert!(
            deployment.contains(required),
            "deployment docs must cover protected auth backup/restore (`{required}`)"
        );
    }
    let example = read_relative("docs/examples/auth.yaml");
    assert!(example.contains("credentials: {}"));
    assert!(example.contains("secret slots"));
    assert!(example.contains("access") && example.contains("refresh"));
    assert!(!example.contains("only structural metadata"));
}

#[test]
fn readme_source_and_protocol_status_matches_current_rss_paths() {
    let gateway = read_relative("src/bin/rustscript-agent-gateway.rs");
    assert!(gateway.contains("source_env_value(\"RUSTSCRIPT_AGENT_SOURCE\""));
    assert!(gateway.contains("source_env_value(\"RUSTSCRIPT_AGENT_SCRIPT\""));
    let source_policy = read_relative("rss/agent/source_policy.rss");
    assert!(source_policy.contains("decision: map = bundled_success()"));
    assert!(source_policy.contains("field_present(context, \"source\")"));
    assert!(source_policy.contains("field_present(context, \"legacy_script\")"));

    let dispatch = read_relative("rss/llm/provider_dispatch.rss");
    assert!(dispatch.contains("provider == \"openai-codex\" && protocol == \"codex-responses\""));
    assert!(dispatch.contains("dispatch_openai_chat(context, request, credential_id)"));
    let openai_chat = read_relative("rss/llm/openai_opaque_chat.rss");
    assert!(openai_chat.contains("chat_send_buffered"));
    assert!(openai_chat.contains("chat_send_stream"));
    assert!(openai_chat.contains("provider_runtime::call"));
    let codex_responses = read_relative("rss/providers/opaque_responses.rss");
    assert!(codex_responses.contains("Task8 access-only scope"));
    assert!(codex_responses.contains("run_responses_stream"));
    let custom_responses = read_relative("rss/llm/openai_responses.rss");
    assert!(custom_responses.contains("\"not_implemented\""));
    assert!(custom_responses.contains("never sends"));
    let anthropic = read_relative("rss/llm/anthropic_messages.rss");
    assert!(anthropic.contains("\"not_implemented\""));

    let readme = read_relative("README.md");
    for required in [
        "RUSTSCRIPT_AGENT_SOURCE",
        "RUSTSCRIPT_AGENT_SCRIPT",
        "bundled:coding",
        "agent.source",
        "OpenAI Chat Completions",
        "Codex Responses",
        "custom Responses",
        "Anthropic Messages",
        "Access-only",
        "refresh",
        "not_implemented",
    ] {
        assert!(
            readme.contains(required),
            "README.md must state the current source/protocol boundary (`{required}`)"
        );
    }
    assert!(
        !readme.contains("blocked by core (A3)"),
        "README.md must not retain the obsolete blanket A3-blocked status"
    );
    assert!(
        !readme.contains("gateway binary still runs `RUSTSCRIPT_AGENT_SCRIPT`"),
        "README.md must not claim the legacy script variable is authoritative"
    );
}

#[test]
fn readme_distinguishes_config_bridge_from_composed_package_acceptance() {
    let auth_host = read_relative("src/auth/host.rs");
    assert!(auth_host.contains("\"config::load_snapshot\""));
    let readme = read_relative("README.md");
    let normalized_readme = readme.split_whitespace().collect::<Vec<_>>().join(" ");
    for required in [
        "config::load_snapshot",
        "Package-level end-to-end config/auth/provider acceptance",
        "final composed-candidate acceptance",
        "remote delivery remain open",
    ] {
        assert!(
            normalized_readme.contains(required),
            "README.md must separate the current bridge from later acceptance (`{required}`)"
        );
    }
}

#[test]
fn configuration_documents_authoritative_source_selection_semantics() {
    // Derive the exact contract tokens from the owning RSS policy so the docs
    // and the policy cannot diverge.
    let policy = read_relative("rss/agent/source_policy.rss");
    assert!(
        policy.contains("bundled:coding"),
        "source policy must admit the bundled coding token"
    );
    for code in ["invalid_agent_source", "unsupported_agent_source"] {
        assert!(
            policy.contains(code),
            "source policy must own the static error code {code}"
        );
    }

    let configuration = read_relative("docs/configuration.md");
    for required in [
        "RUSTSCRIPT_AGENT_SOURCE",
        "PD_EDGE_AGENT_SOURCE",
        "RUSTSCRIPT_AGENT_SCRIPT",
        "bundled:coding",
        "invalid_agent_source",
        "unsupported_agent_source",
        "file:",
    ] {
        assert!(
            configuration.contains(required),
            "docs/configuration.md must document the source-selection token `{required}`"
        );
    }
    // A relative `file:` path is rejected by the policy (absolute only) and a
    // legacy bare path migrates with the deprecated-override indicator; both
    // must be described, not left as an implied default.
    let normalized = configuration.to_lowercase();
    assert!(
        normalized.contains("absolute"),
        "source-selection docs must state the absolute-path requirement"
    );
    assert!(
        normalized.contains("deprecat"),
        "source-selection docs must describe the legacy deprecation/override"
    );
}

#[test]
fn configuration_does_not_claim_production_lacks_the_config_bridge() {
    // The production auth host module registers `config::load_snapshot`; the
    // docs must not state the opposite (the previous Stage-A-only wording).
    let host = read_relative("src/auth/host.rs");
    assert!(
        host.contains("config::load_snapshot"),
        "auth_host_module must register config::load_snapshot"
    );
    let configuration = read_relative("docs/configuration.md");
    assert!(
        configuration.contains("config::load_snapshot"),
        "docs/configuration.md must name the production config bridge"
    );
    for stale in [
        "do not register that bridge",
        "do not register the bridge",
        "AgentRunner` do not register",
    ] {
        assert!(
            !configuration.contains(stale),
            "docs/configuration.md must not claim the production bridge is absent ({stale:?})"
        );
    }
}

#[test]
fn configuration_qualifies_the_internal_test_input_as_non_production() {
    // `RUSTSCRIPT_AGENT_TEST_TMP` is a test-only helper read from `#[cfg(test)]`
    // code, not a gateway setting. It must be documented as internal test input
    // (never renamed away or silently skipped) with an explicit qualifier.
    let configuration = read_relative("docs/configuration.md");
    let start = configuration
        .find("## Environment variables (gateway binary)")
        .expect("configuration.md must keep the canonical env table heading");
    let rest = &configuration[start..];
    let end = rest[1..]
        .find("\n## ")
        .map(|offset| offset + 1)
        .unwrap_or(rest.len());
    let section = &rest[..end];
    assert!(
        section.contains("RUSTSCRIPT_AGENT_TEST_TMP"),
        "the canonical env section must document the internal test input"
    );
    let lowered = section.to_lowercase();
    let window = lowered
        .find("rustscript_agent_test_tmp")
        .map(|index| &lowered[index..])
        .expect("present");
    let head: String = window.chars().take(240).collect();
    assert!(
        head.contains("test") && (head.contains("not") || head.contains("internal")),
        "the internal test input must be qualified as non-production: {head:?}"
    );
}

#[test]
fn docs_examples_decode_through_the_bounded_config_and_auth_loaders() {
    let config_yaml = read_relative("docs/examples/config.yaml");
    let auth_yaml = read_relative("docs/examples/auth.yaml");

    let config = ConfigFile::from_str(&config_yaml).expect("docs/examples/config.yaml must load");
    let auth = AuthConfig::from_str(&auth_yaml).expect("docs/examples/auth.yaml must load");

    assert_eq!(config.version, 1, "example config must be version 1");
    assert_eq!(
        config.agent.source, "bundled:coding",
        "example config must select the bundled coding default"
    );
    assert!(
        !config.model.provider.is_empty() && !config.model.model.is_empty(),
        "example config must name a provider and model"
    );
    // Every provider credential reference must resolve; an empty credential
    // store only validates when no example provider references a credential.
    config
        .validate_auth_references(&auth)
        .expect("example config references must resolve against the example auth store");
    assert!(
        auth.credentials.is_empty(),
        "the shipped example auth store must stay empty (no synthetic credentials)"
    );
    for provider in config.providers.values() {
        assert!(
            provider.auth.is_none(),
            "no example provider may reference a credential ID"
        );
    }
}

#[test]
fn docs_example_auth_has_no_secret_material() {
    let auth_yaml = read_relative("docs/examples/auth.yaml");
    let lowered = auth_yaml.to_lowercase();
    for forbidden in [
        "access_token",
        "refresh_token",
        "api_key",
        "authorization",
        "bearer ",
        "password",
        "client_secret",
    ] {
        assert!(
            !lowered.contains(forbidden),
            "docs/examples/auth.yaml must not contain credential material ({forbidden:?})"
        );
    }
    // No long opaque token-like literal.
    for line in auth_yaml.lines() {
        let value = line.split_once(':').map(|(_, value)| value.trim());
        if let Some(value) = value {
            assert!(
                value.len() <= 64 || value.starts_with('#'),
                "docs/examples/auth.yaml must not embed a token-like literal: {line:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Real RSS source-selection gate over the shipped example.
// ---------------------------------------------------------------------------

fn json_to_vm(value: &serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(value) => Value::Bool(*value),
        serde_json::Value::Number(value) => value
            .as_i64()
            .map(Value::Int)
            .or_else(|| value.as_f64().map(Value::Float))
            .unwrap_or(Value::Null),
        serde_json::Value::String(value) => Value::string(value),
        serde_json::Value::Array(values) => {
            Value::Array(values.iter().map(json_to_vm).collect::<Vec<_>>().into())
        }
        serde_json::Value::Object(entries) => Value::map(
            entries
                .iter()
                .map(|(key, value)| (Value::string(key), json_to_vm(value)))
                .collect(),
        ),
    }
}

/// Builds the RSS-visible public-config value the same way the production
/// `config::load_snapshot` host does: the loaded `ConfigFile` JSON with the
/// provider map projected to the admitted `ProviderEntry` array.
fn public_config_value(config: &ConfigFile) -> Value {
    let mut public = serde_json::to_value(config).expect("config serialises");
    let providers = public
        .get("providers")
        .and_then(|value| value.as_object())
        .map(|map| {
            map.iter()
                .map(|(name, provider)| {
                    serde_json::json!({
                        "name": name,
                        "protocol": provider.get("protocol").cloned().unwrap_or(serde_json::Value::Null),
                        "base_url": provider.get("base_url").cloned().unwrap_or(serde_json::Value::Null),
                        "auth": provider.get("auth").cloned().unwrap_or(serde_json::Value::Null),
                        "oauth": provider.get("oauth").cloned().unwrap_or(serde_json::Value::Null),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    public["providers"] = serde_json::Value::Array(providers);
    // Match the production display-only WorkspaceConfig projection. These
    // fixture paths do not grant authority and no workspace host is invoked.
    let workspaces = &config.workspaces;
    public["workspaces"] = serde_json::json!({
        "allowed_roots": workspaces.allowed_roots.iter()
            .map(|path| path.to_string_lossy().into_owned()).collect::<Vec<_>>(),
        "default": workspaces.default.as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        "named": workspaces.named.iter()
            .map(|(name, path)| serde_json::json!({"name": name, "path": path.to_string_lossy()}))
            .collect::<Vec<_>>(),
        "generation": 1,
    });
    json_to_vm(&public)
}

/// Runs the real `rss/config/selection.rss` `effective_selection` entry with a
/// public config and optional provider override, returning the typed result.
///
/// `effective_selection` performs no host calls, so a fresh VM with the module
/// root frame driven to halt is sufficient (the proven pure-RSS invocation
/// pattern).
fn run_effective_selection(public_config: Value, provider_override: Value) -> Value {
    let source = read_relative("rss/config/selection.rss");
    let catalog = rustscript_agent::auth::host::auth_host_catalog();
    let options = CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog));
    let program =
        compile_source_with_flavor_and_options(source.as_str(), SourceFlavor::RustScript, options)
            .expect("rss/config/selection.rss must compile against the auth host catalog")
            .program;
    // `effective_selection` performs no host calls, but its typed parameters
    // use the admitted named struct `BoundedPublicConfig`, so the catalog's
    // named-struct schemas must be installed for invocation-time resolution.
    let mut registry = HostFunctionRegistry::new();
    registry
        .install_named_struct_schemas(catalog_named_struct_schemas(catalog.as_ref()))
        .expect("install catalog named-struct schemas");
    let mut vm = Vm::try_new(program).expect("fresh VM for selection policy");
    registry
        .bind_vm_cached(&mut vm)
        .expect("bind selection VM registry");
    assert_eq!(
        vm.run().expect("run selection module root"),
        VmStatus::Halted
    );
    let callable = vm
        .resolve_exported_callable("effective_selection")
        .expect("selection module must export effective_selection");
    vm.set_fuel(5_000_000);
    let mut invocation = vm
        .start_invocation(callable, vec![public_config, provider_override])
        .expect("start effective_selection invocation");
    loop {
        match invocation.poll_next().expect("poll invocation") {
            InvocationPoll::Pending => std::thread::sleep(std::time::Duration::from_millis(1)),
            InvocationPoll::Ready(Some(Ok(InvocationItem::Complete(value)))) => return value,
            InvocationPoll::Ready(Some(Ok(InvocationItem::Event(value)))) => {
                panic!("effective_selection emitted an unexpected event: {value:?}")
            }
            InvocationPoll::Ready(Some(Err(error))) => {
                panic!("effective_selection invocation failed: {error:?}")
            }
            InvocationPoll::Ready(None) => panic!("effective_selection stream ended early"),
        }
    }
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    let Value::Map(entries) = value else {
        panic!("expected a map, got {value:?}");
    };
    entries
        .iter()
        .find_map(|(k, v)| match k {
            Value::String(name) if name.as_ref() == key => Some(v),
            _ => None,
        })
        .unwrap_or_else(|| panic!("map is missing field {key}: {value:?}"))
}

fn optional_field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let Value::Map(entries) = value else {
        panic!("expected a map, got {value:?}");
    };
    entries.iter().find_map(|(k, v)| match k {
        Value::String(name) if name.as_ref() == key => Some(v),
        _ => None,
    })
}

fn text(value: &Value) -> String {
    match value {
        Value::String(value) => value.to_string(),
        other => panic!("expected a string, got {other:?}"),
    }
}

#[test]
fn docs_example_selection_runs_through_the_real_rss_source_selection() {
    let config_yaml = read_relative("docs/examples/config.yaml");
    let config = ConfigFile::from_str(&config_yaml).expect("example config must load");
    let public = public_config_value(&config);

    // No override: the example's configured model.provider is selected by the
    // real RSS entry (the shipped example configures that provider entry).
    let selected = run_effective_selection(public.clone(), Value::Null);
    assert_eq!(field(&selected, "ok"), &Value::Bool(true), "{selected:?}");
    assert_eq!(text(field(&selected, "provider")), config.model.provider);
    assert_eq!(text(field(&selected, "model")), config.model.model);
    assert_eq!(text(field(&selected, "source")), config.agent.source);
    // A successful selection carries no error (the optional `error` field is
    // absent when null).
    assert!(
        optional_field(&selected, "error").is_none_or(|value| matches!(value, Value::Null)),
        "a successful selection must not carry an error: {selected:?}"
    );
    // The selection must be for a provider the example actually admits.
    assert!(
        config.providers.contains_key(&config.model.provider),
        "example model.provider must name a configured provider"
    );

    // An explicit non-empty override that is not admitted fails static.
    let missing = run_effective_selection(public.clone(), Value::string("not-admitted"));
    assert_eq!(field(&missing, "ok"), &Value::Bool(false), "{missing:?}");
    assert_eq!(text(field(&missing, "error")), "provider_not_found");

    // An explicit empty override requires a provider.
    let empty_override = run_effective_selection(public, Value::string(""));
    assert_eq!(
        field(&empty_override, "ok"),
        &Value::Bool(false),
        "{empty_override:?}"
    );
    assert_eq!(text(field(&empty_override, "error")), "provider_required");
}
