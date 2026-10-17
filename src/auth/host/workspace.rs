//! Production workspace admission host functions.
//!
//! `workspace::open` consumes the SAME production typed resource authority as
//! the rest of [`super`] (`auth.policy` -> `Owner` -> immutable
//! `Snapshot.config`). It borrows the caller's live policy resource, revalidates
//! concrete resource/arena/bound-owner identity, cancellation, deadline and
//! revocation, checks the selection generation against the frozen snapshot
//! generation, then authorizes an existing directory against the trusted
//! `workspaces.allowed_roots` **from that same owner snapshot**.
//!
//! The opened directory is retained as a native held-directory capability: the
//! no-follow root descriptor is captured once, at admission, and later
//! file/process effects adopt it rather than re-resolving a path string, so a
//! symlink or root replacement after admission cannot redirect an effect into
//! another tree.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use rustscript_vm::resource::{CloseProgress, HostResource, ResourceCloseReason, ResourceResult};
use rustscript_vm::{
    CallOutcome, HostFunctionDescriptor, HostParamPassing, HostParamSchema, HostResourceType,
    HostResourceTypeMeta, HostTypeSchema, Value, Vm, VmResult,
};

use super::{Owner, Policy, error, field, handle, natural, object, string};
use crate::capabilities::vm_io::{
    ConfinedFsLimits, ConfinedFsRoot, MAX_COMPONENT_BYTES, MAX_ENUM_ENTRIES, MAX_READ_BYTES,
    MAX_WRITE_BYTES,
};

/// Public bounded selector: an original-spelling path plus the policy
/// generation the caller observed. Native never trims, normalizes or defaults
/// the token; RSS owns that interpretation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkspaceSelection {
    pub path: String,
    pub policy_generation: u64,
}

/// Maximum Unicode scalars and native bytes of a bounded external selector.
pub const MAX_SELECTOR_SCALARS: usize = 4096;
pub const MAX_SELECTOR_BYTES: usize = 64 * 1024;

/// One retained, admitted directory: the no-follow root descriptor opened once
/// at admission, never reopened from its metadata string.
#[derive(Debug)]
pub struct HeldDirectory {
    root: ConfinedFsRoot,
    canonical_path: String,
}

impl HeldDirectory {
    /// Opens and retains `path` as a trusted directory capability.
    ///
    /// The caller has already validated the path shape and authorized the
    /// canonical path against the frozen allowed roots; this performs only the
    /// actual no-follow directory open.
    pub(crate) fn open(path: &Path, canonical_path: String) -> Result<Self, String> {
        let root = ConfinedFsRoot::with_limits(
            path,
            ConfinedFsLimits {
                max_read_bytes: MAX_READ_BYTES,
                max_write_bytes: MAX_WRITE_BYTES,
                max_entries: MAX_ENUM_ENTRIES,
                max_entry_name_bytes: MAX_COMPONENT_BYTES,
                max_temp_attempts: 32,
            },
        )
        .map_err(|_| "workspace_open_failed".to_string())?;
        Ok(Self {
            root,
            canonical_path,
        })
    }

    fn from_root(root: ConfinedFsRoot, canonical_path: String) -> Self {
        Self {
            root,
            canonical_path,
        }
    }

    /// The canonical admitted path; display/persistence only.
    pub fn canonical_path(&self) -> &str {
        &self.canonical_path
    }

    /// Whether the retained root binding still resolves to the admitted tree.
    pub fn revalidate(&self) -> bool {
        self.root.revalidate_binding()
    }

    /// The retained root capability for native range IO/process adoption.
    pub fn root(&self) -> &ConfinedFsRoot {
        &self.root
    }
}

/// Owner-bound capability retained by a run after the VM arena closes.
pub(crate) struct WorkspaceGrant {
    owner: Arc<Owner>,
    held: Arc<HeldDirectory>,
    generation: u64,
}

impl WorkspaceGrant {
    pub(super) fn from_parts(owner: Arc<Owner>, held: Arc<HeldDirectory>) -> Arc<Self> {
        let generation = owner.snapshot.generation;
        Arc::new(Self {
            owner,
            held,
            generation,
        })
    }

    pub(crate) fn held(&self) -> &Arc<HeldDirectory> {
        &self.held
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn check(&self) -> Result<(), String> {
        self.owner.workspace_check().map_err(str::to_string)?;
        if self.generation != self.owner.snapshot.generation {
            return Err("workspace_generation_stale".to_string());
        }
        if !self.held.revalidate() {
            return Err("workspace_binding_changed".to_string());
        }
        Ok(())
    }
}

/// The published directory resource. It pins the owner so every later borrow
/// revalidates the same authority.
pub(crate) struct WorkspaceDirectory {
    owner: Arc<Owner>,
    held: Arc<HeldDirectory>,
    generation: u64,
}

impl WorkspaceDirectory {
    pub(crate) fn held(&self) -> Arc<HeldDirectory> {
        Arc::clone(&self.held)
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}

impl HostResource for WorkspaceDirectory {
    fn resource_type_key() -> Option<rustscript_vm::ResourceTypeKey> {
        Some(rustscript_vm::ResourceTypeKey::new(Self::KEY).expect("static key"))
    }
    fn begin_close(&mut self, _: ResourceCloseReason) -> ResourceResult<CloseProgress> {
        Ok(CloseProgress::Ready)
    }
}

impl HostResourceType for WorkspaceDirectory {
    const KEY: &'static str = "workspace.directory";
    const DESCRIPTION: &'static str = "Admitted confined workspace directory";
}

impl super::OwnerResource for WorkspaceDirectory {
    fn owner(&self) -> Arc<Owner> {
        Arc::clone(&self.owner)
    }
}

/// Validates the bounded public selector token without repairing it.
pub(crate) fn validate_selector(path: &str) -> Result<(), &'static str> {
    if path.is_empty() || path.chars().all(char::is_whitespace) {
        return Err("workspace_selector_blank");
    }
    if path.chars().count() > MAX_SELECTOR_SCALARS || path.len() > MAX_SELECTOR_BYTES {
        return Err("workspace_selector_too_large");
    }
    if path.contains('\0') {
        return Err("workspace_selector_invalid");
    }
    Ok(())
}

/// Component-wise containment: `path` is the same as, or strictly below,
/// `root`. Never a bare string-prefix comparison, so `/root-evil` is not
/// admitted by root `/root`.
pub(crate) fn contained_by(path: &Path, root: &Path) -> bool {
    if !path.is_absolute() || !root.is_absolute() {
        return false;
    }
    let mut path_components = path.components();
    for root_component in root.components() {
        match path_components.next() {
            Some(component) if component == root_component => {}
            _ => return false,
        }
    }
    true
}

/// Canonicalizes an absolute selector without repairing the original token.
///
/// The parent directory of the requested path is canonicalized (following
/// symlinks), and the leaf name is appended. A missing or unreadable parent or
/// a relative/dot-containing token fails closed.
fn canonical_admitted_path(path: &Path) -> Result<PathBuf, &'static str> {
    if !path.is_absolute() {
        return Err("workspace_selector_relative");
    }
    for component in path.components() {
        if matches!(component, Component::ParentDir | Component::CurDir) {
            return Err("workspace_selector_relative");
        }
    }
    let leaf = path
        .file_name()
        .ok_or("workspace_selector_invalid")?
        .to_os_string();
    let parent = path.parent().ok_or("workspace_selector_invalid")?;
    let canonical_parent = parent.canonicalize().map_err(|_| "workspace_unavailable")?;
    Ok(canonical_parent.join(leaf))
}

/// Retains the selected directory by descending from an already-held trusted
/// root. The canonical strings decide which configured descriptor to try, but
/// the selected directory itself is opened only relative to that descriptor.
fn retain_beneath_trusted_root(
    canonical: &Path,
    canonical_path: &str,
    roots: &[PathBuf],
) -> Result<Arc<HeldDirectory>, String> {
    let limits = ConfinedFsLimits {
        max_read_bytes: MAX_READ_BYTES,
        max_write_bytes: MAX_WRITE_BYTES,
        max_entries: MAX_ENUM_ENTRIES,
        max_entry_name_bytes: MAX_COMPONENT_BYTES,
        max_temp_attempts: 32,
    };
    for configured_root in roots {
        if !configured_root.is_absolute() {
            continue;
        }
        let Ok(canonical_root) = configured_root.canonicalize() else {
            continue;
        };
        if !contained_by(canonical, &canonical_root) {
            continue;
        }
        let root_display = canonical_root
            .to_str()
            .ok_or_else(|| "workspace_selector_invalid".to_string())?;
        let Ok(root) = HeldDirectory::open(configured_root, root_display.to_string()) else {
            continue;
        };
        if !root.root.revalidate_binding()
            || configured_root.canonicalize().ok().as_deref() != Some(canonical_root.as_path())
        {
            continue;
        }
        let Ok(relative) = canonical.strip_prefix(&canonical_root) else {
            continue;
        };
        let retained = if relative.as_os_str().is_empty() {
            root.root.adopt(limits)
        } else if let Some(relative) = relative.to_str() {
            root.root.subroot(relative, limits)
        } else {
            return Err("workspace_selector_invalid".to_string());
        };
        let Ok(retained) = retained else {
            continue;
        };
        let held = Arc::new(HeldDirectory::from_root(
            retained,
            canonical_path.to_string(),
        ));
        if !root.root.revalidate_binding() || !held.revalidate() {
            continue;
        }
        return Ok(held);
    }
    Err("workspace_denied".to_string())
}

/// Retains `path` after checking the frozen allowed roots of THIS owner.
pub(super) fn admit(
    owner: &Arc<Owner>,
    selection: &WorkspaceSelection,
) -> Result<Arc<HeldDirectory>, String> {
    owner.workspace_check().map_err(str::to_string)?;
    if selection.policy_generation != owner.snapshot.generation {
        return Err("workspace_generation_stale".to_string());
    }
    let path = PathBuf::from(&selection.path);
    let canonical = canonical_admitted_path(&path).map_err(str::to_string)?;
    let canonical_path = canonical
        .to_str()
        .ok_or_else(|| "workspace_selector_invalid".to_string())?
        .to_string();
    let held = retain_beneath_trusted_root(
        &canonical,
        &canonical_path,
        &owner.snapshot.config.workspaces.allowed_roots,
    )?;
    // Revalidate authority after the open and before publication.
    owner.workspace_check().map_err(str::to_string)?;
    if !held.revalidate() {
        return Err("workspace_replaced".to_string());
    }
    Ok(held)
}

fn selection_type() -> HostTypeSchema {
    super::named(
        "WorkspaceSelection",
        vec![
            ("path", HostTypeSchema::String),
            ("policy_generation", HostTypeSchema::Int),
        ],
    )
}

fn result_type() -> HostTypeSchema {
    super::named(
        "WorkspaceOpenResult",
        vec![
            ("ok", HostTypeSchema::Bool),
            (
                "error",
                super::opt(super::named(
                    "WorkspaceHostError",
                    vec![("code", HostTypeSchema::String)],
                )),
            ),
            ("directory", super::opt(super::key(WorkspaceDirectory::KEY))),
            ("canonical_path", super::opt(HostTypeSchema::String)),
            ("policy_generation", super::opt(HostTypeSchema::Int)),
        ],
    )
}

fn workspace_error(code: &str) -> Value {
    object(vec![("code", Value::string(code))])
}

fn denied(code: &str) -> Value {
    object(vec![
        ("ok", Value::Bool(false)),
        ("directory", Value::Null),
        ("canonical_path", Value::Null),
        ("policy_generation", Value::Null),
        ("error", workspace_error(code)),
    ])
}

pub fn open_descriptor() -> HostFunctionDescriptor {
    super::desc(
        "workspace::open",
        vec![
            super::param("selection", selection_type()),
            super::borrow("policy_handle", super::key(Policy::KEY)),
        ],
        result_type(),
        open_call,
    )
}

/// Typed-denial variant used by the restricted RSS entry so a denial is a
/// value rather than a host error.
pub fn open_result_descriptor() -> HostFunctionDescriptor {
    super::desc(
        "workspace::open_result",
        vec![
            super::param("selection", selection_type()),
            super::borrow("policy_handle", super::key(Policy::KEY)),
        ],
        result_type(),
        open_result_call,
    )
}

fn open_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let selection = args.first().ok_or_else(|| error("invalid_request"))?;
    let policy = args.get(1).ok_or_else(|| error("invalid_request"))?;
    let (value, failure) = open_shared(vm, selection, policy)?;
    match failure {
        Some(code) => Err(error(&code)),
        None => super::result(value),
    }
}

fn open_result_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let selection = args.first().ok_or_else(|| error("invalid_request"))?;
    let policy = args.get(1).ok_or_else(|| error("invalid_request"))?;
    let (value, _failure) = open_shared(vm, selection, policy)?;
    super::result(value)
}

fn open_shared(
    vm: &mut Vm,
    selection: &Value,
    policy: &Value,
) -> VmResult<(Value, Option<String>)> {
    // Concrete resource, arena, bound-owner identity and revocation checks.
    let owner = match super::borrowed::<Policy>(vm, policy) {
        Ok(owner) => owner,
        Err(_) => {
            return Ok((
                denied("workspace_unauthorized"),
                Some("workspace_unauthorized".into()),
            ));
        }
    };
    let path = string(field(selection, "path")?)?;
    let generation = natural(field(selection, "policy_generation")?)?;
    let selection = WorkspaceSelection {
        path: path.to_string(),
        policy_generation: generation,
    };
    if let Err(code) = validate_selector(&selection.path) {
        return Ok((denied(code), Some(code.to_string())));
    }
    let held = match admit(&owner, &selection) {
        Ok(held) => held,
        Err(code) => return Ok((denied(&code), Some(code))),
    };
    let canonical = held.canonical_path().to_string();
    if let Err(code) = owner.workspace_check() {
        return Ok((denied(code), Some(code.to_string())));
    }
    let issued = super::issue(
        vm,
        WorkspaceDirectory {
            owner: owner.clone(),
            held,
            generation: owner.snapshot.generation,
        },
    )?;
    if let Err(code) = owner.workspace_check() {
        let _ = vm
            .host_context()
            .close_resource::<WorkspaceDirectory>(handle(&issued)?, ResourceCloseReason::Requested);
        return Ok((denied(code), Some(code.to_string())));
    }
    Ok((
        object(vec![
            ("ok", Value::Bool(true)),
            ("directory", issued),
            ("canonical_path", Value::string(canonical)),
            (
                "policy_generation",
                Value::Int(owner.snapshot.generation as i64),
            ),
            ("error", Value::Null),
        ]),
        None,
    ))
}

/// Borrows a live admitted directory resource for later native adoption.
///
/// Revalidates the owner identity, revocation/cancellation/deadline, the
/// reserved policy generation and the retained root binding before returning
/// the held descriptor.
pub(super) fn borrow_held(
    vm: &mut Vm,
    value: &Value,
) -> VmResult<(Arc<Owner>, Arc<HeldDirectory>)> {
    let owner = super::borrowed::<WorkspaceDirectory>(vm, value)?;
    let (held, generation) = {
        let context = vm.host_context();
        let entry = context
            .borrow_resource_with_key::<WorkspaceDirectory>(
                handle(value)?,
                &rustscript_vm::ResourceTypeKey::new(WorkspaceDirectory::KEY).expect("static key"),
            )
            .map_err(|_| error("resource_invalid"))?;
        (entry.held(), entry.generation())
    };
    owner.workspace_check().map_err(error)?;
    if generation != owner.snapshot.generation {
        return Err(error("workspace_generation_stale"));
    }
    if !held.revalidate() {
        return Err(error("workspace_replaced"));
    }
    Ok((owner, held))
}

pub fn close_descriptor() -> HostFunctionDescriptor {
    super::desc(
        "workspace::close",
        vec![HostParamSchema::with_passing(
            "handle",
            super::key(WorkspaceDirectory::KEY),
            HostParamPassing::TakeOwned,
        )],
        HostTypeSchema::Null,
        close_call,
    )
}

fn close_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    super::borrowed::<WorkspaceDirectory>(vm, &args[0])?;
    vm.host_context()
        .close_resource::<WorkspaceDirectory>(handle(&args[0])?, ResourceCloseReason::Requested)
        .map_err(|_| error("resource_invalid"))?;
    super::result(Value::Null)
}

pub fn directory_meta() -> HostResourceTypeMeta {
    HostResourceTypeMeta::of::<WorkspaceDirectory>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CancellationReason;
    use crate::auth::host::{AuthHost, auth_host_catalog};
    use crate::capabilities::{
        AllowAllApproval, CapabilityLifecycle, CapabilityOwner, CapabilityRisk, DurableStarted,
        DurableToolLifecycle, FilesystemCapability, FilesystemLimits, LifecycleClock,
        LifecycleError, LifecycleLimits, NeverCancelled, PrepareMetadata, PrepareOutcome,
        ProcessCapability, ProcessLimits, SystemClock, TokenIssuer, UuidIssuer,
    };
    use crate::runtime::RunCancellation;
    use rustscript_vm::{
        CompileSourceFileOptions, HostFunctionRegistry, SourceFlavor, Value, Vm, VmStatus,
        compile_source_at_path_with_flavor_and_options,
    };
    use std::sync::Arc;
    use std::time::Duration;

    const OPEN_SOURCE: &str = r#"
        use config;
        use workspace;
        pub fn open(home: resource<auth.host_home>, path: string) -> WorkspaceOpenResult {
            let snapshot = config::load_snapshot(&home);
            let selection: WorkspaceSelection = {
                path: path,
                policy_generation: snapshot.policy_generation
            };
            workspace::open_result(selection, &snapshot.policy_handle)
        }
    "#;

    struct Fixture {
        root: PathBuf,
        home: PathBuf,
        workspace: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let temp = PathBuf::from(
                std::env::var("RUSTSCRIPT_AGENT_TEST_TMP").expect("assigned test temp"),
            );
            let root = temp.join(format!(
                "workspace-native-{label}-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            let home = root.join("home");
            let workspace = root.join("workspace");
            std::fs::create_dir_all(&home).expect("private home");
            std::fs::create_dir_all(&workspace).expect("workspace");
            let config = format!(
                "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n",
                workspace.display(),
                workspace.display(),
            );
            crate::config_file::ConfigFile::from_str(&config).expect("synthetic config");
            std::fs::write(home.join("config.yaml"), config).expect("write config");
            std::fs::write(home.join("auth.yaml"), "version: 1\ncredentials: {}\n")
                .expect("write empty credentials");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
                    .expect("home permissions");
                for name in ["config.yaml", "auth.yaml"] {
                    std::fs::set_permissions(
                        home.join(name),
                        std::fs::Permissions::from_mode(0o600),
                    )
                    .expect("private config permissions");
                }
            }
            Self {
                root,
                home,
                workspace,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    struct NativeDurable;

    impl DurableToolLifecycle for NativeDurable {
        fn assert_active_run(&self, _: &str) -> Result<(), LifecycleError> {
            Ok(())
        }

        fn prepare_parent(&self, _: &str, _: &str, _: &str) -> Result<(), LifecycleError> {
            Ok(())
        }

        fn replay_result(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<Option<serde_json::Value>, LifecycleError> {
            Ok(None)
        }

        fn commit_started(&self, _: &DurableStarted) -> Result<(), LifecycleError> {
            Ok(())
        }

        fn commit_result(
            &self,
            _: &str,
            result: &serde_json::Value,
        ) -> Result<serde_json::Value, LifecycleError> {
            Ok(result.clone())
        }

        fn interrupt(&self, _: &str) -> Result<(), LifecycleError> {
            Ok(())
        }
    }

    fn native_lifecycle(path: &Path) -> (CapabilityLifecycle, CapabilityOwner) {
        let owner = CapabilityOwner::new("native-test", "workspace-test", "effect-run")
            .expect("native capability owner");
        let clock = Arc::new(SystemClock);
        let deadline_ms = clock.now_ms() + 60_000;
        let lifecycle = CapabilityLifecycle::builder()
            .owner(owner.clone())
            .registry_identity("workspace-native-test")
            .workspace(path)
            .limits(LifecycleLimits {
                max_tool_calls: 8,
                max_output_bytes: 16 * 1024,
                max_summary_bytes: 128,
            })
            .deadline_ms(deadline_ms)
            .clock(clock)
            .tokens(Arc::new(UuidIssuer) as Arc<dyn TokenIssuer>)
            .durable(Arc::new(NativeDurable))
            .approval(Arc::new(AllowAllApproval))
            .cancellation(Arc::new(NeverCancelled))
            .build()
            .expect("synthetic lifecycle");
        (lifecycle, owner)
    }

    fn native_token(
        lifecycle: &CapabilityLifecycle,
        owner: &CapabilityOwner,
        risk: CapabilityRisk,
        call_id: &str,
    ) -> String {
        match lifecycle
            .prepare(
                owner,
                PrepareMetadata {
                    run_id: owner.run().to_string(),
                    call_id: call_id.to_string(),
                    tool_name: "native_workspace_effect".to_string(),
                    argument_digest: "synthetic-test-digest".to_string(),
                    registry_identity: "workspace-native-test".to_string(),
                    risk_class: risk,
                    summary: "native workspace effect".to_string(),
                },
            )
            .expect("prepare synthetic native effect")
        {
            PrepareOutcome::Execute {
                execution_token, ..
            } => execution_token,
            PrepareOutcome::Replay { .. } => panic!("fresh native test call cannot replay"),
        }
    }

    fn typed_open_vm(host: &AuthHost) -> (Vm, Value) {
        let source_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rss/agent/workspace.rss");
        let catalog = auth_host_catalog();
        let compiled = compile_source_at_path_with_flavor_and_options(
            &source_path,
            OPEN_SOURCE,
            SourceFlavor::RustScript,
            CompileSourceFileOptions::default().with_host_api_catalog(catalog.clone()),
        )
        .expect("compile restricted native workspace call");
        let mut vm = Vm::new_shared(Arc::new(compiled.program));
        let mut registry = HostFunctionRegistry::restricted();
        host.register(&mut registry, catalog.as_ref())
            .expect("install production auth/workspace host");
        registry
            .bind_vm_cached(&mut vm)
            .expect("bind restricted host");
        assert!(matches!(vm.run().expect("RSS root"), VmStatus::Halted));
        let context = host.bind_vm(&mut vm).expect("bind native owner");
        let home = map_field(&context, "host_home")
            .expect("typed host_home resource")
            .clone();
        (vm, home)
    }

    fn map_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
        let Value::Map(fields) = value else {
            return None;
        };
        fields.iter().find_map(|(key, value)| match key {
            Value::String(key) if key.as_ref() == name => Some(value),
            _ => None,
        })
    }

    fn invoke_open(vm: &mut Vm, home: &Value, path: &Path) -> Value {
        let callable = vm.resolve_exported_callable("open").expect("RSS export");
        vm.invoke_callable(
            callable,
            &[home.clone(), Value::string(path.to_string_lossy())],
        )
        .expect("restricted RSS workspace host call")
    }

    fn admitted_grant(
        host: &AuthHost,
        vm: &mut Vm,
        home: &Value,
        path: &Path,
    ) -> Arc<WorkspaceGrant> {
        let result = invoke_open(vm, home, path);
        assert!(matches!(map_field(&result, "ok"), Some(Value::Bool(true))));
        let directory = map_field(&result, "directory").expect("typed directory resource");
        host.take_workspace_directory(vm, directory)
            .expect("adopt native resource while VM arena is live")
    }

    #[test]
    fn reload_invalidates_old_workspace_grant_without_changing_owner_check() {
        let fixture = Fixture::new("epoch");
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
        let host =
            AuthHost::new(fixture.home.clone(), cancellation).expect("empty-credential host");
        let (mut vm, home) = typed_open_vm(&host);
        let grant = admitted_grant(&host, &mut vm, &home, &fixture.workspace);
        assert!(grant.check().is_ok());

        assert_eq!(host.reload().expect("publish workspace epoch"), 2);
        assert!(
            super::super::bound(&mut vm)
                .expect("old owner remains bound")
                .check()
                .is_ok(),
            "global auth Owner.check retains its existing snapshot behavior"
        );
        assert_eq!(
            grant
                .check()
                .expect_err("old workspace grant must be stale"),
            "workspace_generation_stale"
        );
    }

    #[cfg(unix)]
    #[test]
    fn admitted_root_drives_adopted_file_and_process_capabilities_and_rejects_replacement() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new("effects");
        let outside = fixture.root.join("outside");
        std::fs::create_dir_all(&outside).expect("outside tree");
        std::fs::write(fixture.workspace.join("input.txt"), b"before").expect("input");
        std::fs::write(outside.join("sentinel.txt"), b"outside unchanged").expect("sentinel");
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
        let host =
            AuthHost::new(fixture.home.clone(), cancellation).expect("empty-credential host");
        let (mut vm, home) = typed_open_vm(&host);
        let grant = admitted_grant(&host, &mut vm, &home, &fixture.workspace);
        let (lifecycle, capability_owner) = native_lifecycle(&fixture.workspace);
        let filesystem = FilesystemCapability::new_adopted(
            lifecycle.clone(),
            capability_owner.clone(),
            FilesystemLimits {
                max_read_bytes: 64,
                max_write_bytes: 64,
                max_list_entries: 8,
            },
            Arc::clone(&grant),
        )
        .expect("adopt admitted workspace into filesystem capability");

        let write_token = native_token(
            &lifecycle,
            &capability_owner,
            CapabilityRisk::Write,
            "write-inside",
        );
        filesystem
            .write_atomic(&write_token, "created.txt", "*", b"inside only")
            .expect("admitted native file write");
        let read_token = native_token(
            &lifecycle,
            &capability_owner,
            CapabilityRisk::Read,
            "read-inside",
        );
        assert_eq!(
            filesystem
                .read_range(&read_token, "input.txt", 0, 64)
                .expect("admitted native file read")
                .bytes,
            b"before"
        );
        assert_eq!(
            filesystem
                .read_range(&read_token, "created.txt", 0, 64)
                .expect("read native write back")
                .bytes,
            b"inside only"
        );

        let processes = ProcessCapability::new_adopted(
            lifecycle.clone(),
            capability_owner.clone(),
            ProcessLimits::default(),
            Arc::clone(&grant),
        )
        .expect("adopt admitted workspace into process capability");
        let process_token = native_token(
            &lifecycle,
            &capability_owner,
            CapabilityRisk::Execute,
            "cwd-probe",
        );
        let spawned = processes
            .spawn(
                &process_token,
                &["/bin/pwd".to_string()],
                "",
                &[],
                ProcessLimits::default(),
            )
            .expect("spawn with admitted native cwd");
        let snapshot = processes
            .wait(&process_token, &spawned.handle, Some(5_000))
            .expect("wait for cwd probe");
        assert!(!snapshot.running);
        assert_eq!(snapshot.exit_code, Some(0));
        assert_eq!(snapshot.stdout.trim(), fixture.workspace.to_string_lossy());
        lifecycle
            .commit(
                &capability_owner,
                &process_token,
                serde_json::json!({"ok": true, "content": "completed"}),
            )
            .expect("close process lease");

        let moved = fixture.root.join("workspace-moved");
        std::fs::rename(&fixture.workspace, &moved).expect("replace admitted path");
        symlink(&outside, &fixture.workspace).expect("install outside symlink");
        assert!(grant.check().is_err(), "replaced binding must be rejected");
        assert_eq!(
            filesystem
                .read_range(&read_token, "sentinel.txt", 0, 64)
                .expect_err("adopted reader rejects replaced binding")
                .code(),
            "workspace_denied"
        );
        assert_eq!(
            filesystem
                .write_atomic(&write_token, "sentinel.txt", "*", b"must not escape")
                .expect_err("adopted writer rejects replaced binding")
                .code(),
            "workspace_denied"
        );
        let denied_process = native_token(
            &lifecycle,
            &capability_owner,
            CapabilityRisk::Execute,
            "cwd-after-replace",
        );
        assert_eq!(
            processes
                .spawn(
                    &denied_process,
                    &["/bin/pwd".to_string()],
                    "",
                    &[],
                    ProcessLimits::default(),
                )
                .expect_err("adopted process rejects replaced binding")
                .code(),
            "workspace_denied"
        );
        assert_eq!(
            std::fs::read(outside.join("sentinel.txt")).expect("outside sentinel"),
            b"outside unchanged"
        );
        assert!(!outside.join("created.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn typed_open_rejects_symlink_outside_trusted_root_without_effect() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new("symlink");
        let outside = fixture.root.join("outside");
        std::fs::create_dir_all(&outside).expect("outside tree");
        std::fs::write(outside.join("sentinel.txt"), b"unchanged").expect("sentinel");
        symlink(&outside, fixture.workspace.join("escape")).expect("workspace symlink");
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
        let host =
            AuthHost::new(fixture.home.clone(), cancellation).expect("empty-credential host");
        let (mut vm, home) = typed_open_vm(&host);
        let result = invoke_open(&mut vm, &home, &fixture.workspace.join("escape"));

        assert!(matches!(map_field(&result, "ok"), Some(Value::Bool(false))));
        let code = map_field(map_field(&result, "error").expect("typed denial"), "code")
            .expect("error code");
        assert!(matches!(code, Value::String(code) if code.as_ref() == "workspace_denied"));
        assert_eq!(
            std::fs::read(outside.join("sentinel.txt")).expect("outside sentinel"),
            b"unchanged"
        );
        assert!(
            admitted_grant(&host, &mut vm, &home, &fixture.workspace)
                .check()
                .is_ok(),
            "a denied symlink admission must not poison a later valid workspace resource"
        );
    }

    #[test]
    fn directory_resource_from_another_vm_arena_cannot_be_adopted() {
        let fixture = Fixture::new("foreign-vm");
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
        let host =
            AuthHost::new(fixture.home.clone(), cancellation).expect("empty-credential host");
        let (mut origin, home) = typed_open_vm(&host);
        let (mut foreign, _) = typed_open_vm(&host);
        let result = invoke_open(&mut origin, &home, &fixture.workspace);
        let directory = map_field(&result, "directory").expect("typed directory resource");

        assert!(
            host.take_workspace_directory(&mut origin, directory)
                .is_ok()
        );
        assert!(
            host.take_workspace_directory(&mut foreign, directory)
                .is_err()
        );
        assert!(
            host.take_workspace_directory(&mut origin, &Value::Null)
                .is_err()
        );
    }

    #[test]
    fn workspace_grant_expires_with_its_finite_owner_deadline() {
        let fixture = Fixture::new("deadline");
        let cancellation = RunCancellation::with_timeout(Duration::from_millis(500));
        let host =
            AuthHost::new(fixture.home.clone(), cancellation).expect("empty-credential host");
        let (mut vm, home) = typed_open_vm(&host);
        let grant = admitted_grant(&host, &mut vm, &home, &fixture.workspace);
        assert!(grant.check().is_ok());

        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(
            grant.check().expect_err("expired workspace grant"),
            "workspace_unauthorized"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cancellation_and_dropping_vm_resources_release_workspace_descriptors() {
        fn descriptor_count(path: &Path) -> usize {
            std::fs::read_dir("/proc/self/fd")
                .expect("proc fd table")
                .filter_map(Result::ok)
                .filter(|entry| std::fs::read_link(entry.path()).is_ok_and(|target| target == path))
                .count()
        }

        let fixture = Fixture::new("lease-drop");
        let cancellation = RunCancellation::with_timeout(Duration::from_secs(30));
        let host = AuthHost::new(fixture.home.clone(), cancellation.clone())
            .expect("empty-credential host");
        let (mut vm, home) = typed_open_vm(&host);
        let grant = admitted_grant(&host, &mut vm, &home, &fixture.workspace);
        assert!(descriptor_count(&fixture.workspace) > 0);

        cancellation.request(CancellationReason::Requested);
        assert_eq!(
            grant.check().expect_err("cancelled workspace lease"),
            "workspace_unauthorized"
        );
        drop(grant);
        drop(vm);
        drop(host);
        drop(home);
        assert_eq!(descriptor_count(&fixture.workspace), 0);
    }
}
