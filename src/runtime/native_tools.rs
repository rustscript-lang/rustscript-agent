//! Default tool runtime compiled once from closed embedded catalog bytes.
//!
//! A signed package root, when configured, is a private sibling of the trusted
//! SQLite path. Request JSON never selects that directory or the program.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use super::agent_host::{PinnedToolCode, PinnedToolProgram, PinnedToolReceipt};

pub(crate) const EMBEDDING_GRAPH_ID: &str = "embedding:agent.tools/v1";

/// Trusted package directory derived only from the gateway SQLite path.
pub fn trusted_tool_package_root(sqlite_path: &Path) -> PathBuf {
    let name = sqlite_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state.db");
    let parent = sqlite_path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(".{name}.tool-packages"))
}

/// One compiled embedded dispatcher, shared by runs that have no signed pin.
pub(crate) struct NativeToolRuntime {
    program: Arc<rustscript_vm::Program>,
    entry: String,
    registry: Result<Arc<rustscript_vm::HostFunctionRegistry>, String>,
}

impl NativeToolRuntime {
    pub(crate) fn compile() -> Result<Self, String> {
        let catalog = super::agent_host::agent_host_catalog();
        let mut host_roots = BTreeSet::new();
        host_roots.insert("json".to_string());
        host_roots.insert("bytes".to_string());
        for function in catalog.functions() {
            if let Some((namespace, _)) = function.name.split_once("::") {
                host_roots.insert(namespace.to_string());
            }
        }
        let compiled = super::closed_bundle::compile_embedded_tool_dispatch(&catalog, &host_roots)
            .map_err(|error| format!("compile embedded tool dispatch: {error:?}"))?;
        let entry = compiled
            .entry_name
            .filter(|entry| !entry.is_empty())
            .ok_or_else(|| "embedded tool dispatch has no callable".to_string())?;
        let authorized_imports: Vec<_> = compiled
            .program
            .imports
            .iter()
            .map(|import| import.name.clone())
            .collect();
        // Immutable adapters only; owner, cancellation and invocation witness bind later.
        let registry = super::rss_runner::build_pinned_registry(&authorized_imports)
            .map(Arc::new)
            .map_err(|error| error.to_string());
        Ok(Self {
            program: Arc::new(compiled.program),
            entry,
            registry,
        })
    }

    pub(crate) fn binding_for(
        &self,
        run_id: &str,
        session_id: &str,
        profile: &str,
        registry_identity: &str,
        workspace: PathBuf,
    ) -> PinnedToolProgram {
        PinnedToolProgram::seal(
            PinnedToolCode {
                harness_selection: crate::plugins::HarnessSelection::ToolOnly {
                    tool_package: EMBEDDING_PACKAGE_ID.into(),
                },
                managed_contract: None,
                managed_policy_catalog: None,
                state: None,
                program: Arc::clone(&self.program),
                entry: self.entry.clone(),
                package_id: "embedding".to_string(),
                artifact_id: "embedding".to_string(),
                export: "invoke_prepared".to_string(),
                registry: self.registry.clone(),
                expects_dispatch_input: true,
            },
            PinnedToolReceipt {
                graph_id: EMBEDDING_GRAPH_ID.to_string(),
                generation: 0,
                ref_id: format!("embedding:{run_id}"),
                run_id: run_id.to_string(),
                session_id: session_id.to_string(),
                profile: profile.to_string(),
                registry_identity: registry_identity.to_string(),
                workspace,
            },
            super::agent_host::NativeExecutionAuthority::ExplicitStateless,
        )
    }
}

/// Process-wide embedded dispatcher. Only an explicit stateless host may
/// execute it when no pin is present. Durable missing pins do not use it.
pub(crate) fn shared_embedded_runtime() -> Result<Arc<NativeToolRuntime>, String> {
    static RUNTIME: OnceLock<Result<Arc<NativeToolRuntime>, String>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| NativeToolRuntime::compile().map(Arc::new))
        .clone()
}

pub(crate) const EMBEDDING_PACKAGE_ID: &str = "org.rustscript.embedding.tools";
const EMBEDDING_ENTRY: &str = "rss/tools/dispatch.rss";

pub(crate) fn embedding_package_files()
-> Result<std::collections::BTreeMap<String, Vec<u8>>, String> {
    shared_embedding_package_files().cloned()
}

/// The embedded catalog is a pure function of `bundled_rss_sources`, the fixed
/// host catalog and the fixed entry, so it is built once and shared. Callers
/// receive an owned copy and may mutate it freely.
fn shared_embedding_package_files()
-> Result<&'static std::collections::BTreeMap<String, Vec<u8>>, String> {
    static FILES: OnceLock<Result<std::collections::BTreeMap<String, Vec<u8>>, String>> =
        OnceLock::new();
    FILES
        .get_or_init(build_embedding_package_files)
        .as_ref()
        .map_err(String::clone)
}

fn build_embedding_package_files() -> Result<std::collections::BTreeMap<String, Vec<u8>>, String> {
    let catalog = super::agent_host::agent_host_catalog();
    let mut host_roots = BTreeSet::new();
    host_roots.insert("json".to_string());
    host_roots.insert("bytes".to_string());
    for function in catalog.functions() {
        if let Some((namespace, _)) = function.name.split_once("::") {
            host_roots.insert(namespace.to_string());
        }
    }
    let sources = crate::bundled_rss_sources();
    let keys = super::closed_bundle::select_catalog_closure(
        sources,
        &catalog,
        EMBEDDING_ENTRY,
        &host_roots,
    )
    .map_err(|error| format!("embedding closure: {error:?}"))?;
    let mut files = std::collections::BTreeMap::new();
    files.insert(
        "manifest.yaml".to_string(),
        embedding_manifest().into_bytes(),
    );
    for key in keys {
        let bytes = sources
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, source)| source.as_bytes().to_vec())
            .ok_or_else(|| format!("embedding source missing {key}"))?;
        files.insert(key, bytes);
    }
    Ok(files)
}

pub(crate) fn embedding_payload_matches(payload: &[u8]) -> bool {
    shared_embedding_package_files()
        .ok()
        .is_some_and(|files| crate::plugins::embedding_payload_bytes(files) == payload)
}

fn embedding_manifest() -> String {
    format!(
        r#"format: rustscript.plugin/v1
id: {EMBEDDING_PACKAGE_ID}
version: 1.0.0
kind: tool
runtime: ">=0.1.0, <0.2.0"
contract: agent.tool/v1
host_abi: agent.cap/v1
entry:
  path: {EMBEDDING_ENTRY}
  export: invoke_prepared
dependencies: []
capabilities:
  - clock.read
  - process.spawn
  - workspace.read
  - workspace.write
effects:
  contract: agent.effects/v1
  entries:
    invoke_prepared:
      direct:
        - kind: clock.read
          scope: bound_run
          recovery: none
        - kind: process.spawn
          scope: bound_process
          recovery: none
        - kind: workspace.fs.read
          scope: bound_workspace
          recovery: none
        - kind: workspace.fs.write
          scope: bound_workspace
          recovery: none
      delegated: []
"#
    )
}

#[cfg(test)]
mod tests {
    use super::{
        EMBEDDING_ENTRY, embedding_package_files, embedding_payload_matches,
        shared_embedding_package_files,
    };

    #[test]
    fn embedded_catalog_material_is_built_once_and_shared() {
        let first = shared_embedding_package_files().expect("embedded catalog");
        let second = shared_embedding_package_files().expect("embedded catalog");
        assert!(
            std::ptr::eq(first, second),
            "immutable embedded catalog must be shared, not rebuilt"
        );
        assert!(first.contains_key("manifest.yaml"));
        assert!(first.contains_key(EMBEDDING_ENTRY));
        assert_eq!(first.len(), second.len());
    }

    #[test]
    fn embedded_catalog_copies_isolate_mutation_and_match_real_payloads() {
        let original = embedding_package_files().expect("embedded catalog");
        let expected = crate::plugins::embedding_payload_bytes(&original);
        assert!(embedding_payload_matches(&expected));

        // The returned map is an owned copy: mutating it must not touch the
        // shared immutable material or a later payload comparison.
        let mut mutated = embedding_package_files().expect("embedded catalog");
        mutated.insert("manifest.yaml".into(), b"tampered".to_vec());
        mutated.insert("rss/tools/extra.rss".into(), b"extra".to_vec());
        let mutated_payload = crate::plugins::embedding_payload_bytes(&mutated);
        assert_ne!(mutated_payload, expected);
        assert!(!embedding_payload_matches(&mutated_payload));

        let again = embedding_package_files().expect("embedded catalog");
        assert_eq!(again, original);
        assert_eq!(
            again.get("manifest.yaml").map(Vec::as_slice),
            original.get("manifest.yaml").map(Vec::as_slice)
        );
        assert!(embedding_payload_matches(&expected));

        let mut shortened = expected.clone();
        shortened.truncate(shortened.len() - 1);
        assert!(!embedding_payload_matches(&shortened));
    }
}
