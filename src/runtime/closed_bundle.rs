//! Closed, bounded RSS bundle compilation.
//!
//! This module owns the generic native compile/admission primitive. It parses
//! every supplied source with a caller-supplied dialect, admits only a closed
//! in-memory import graph bounded by caller-supplied limits, and resolves the
//! exact root export through Core's module graph. It carries no auth workflow,
//! no registry grants, no global cache, and no serialization.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustscript_vm::{
    CompileSourceFileOptions, HostApiCatalog, ImportClause, ParserDialect, SharedParserOptions,
    SourceFlavor, UsePathSegment, analyze_source_from_string_with_options,
    compile_source_at_path_with_flavor_and_options, parse_source_with_dialect,
};

/// Whole-catalog bounds of the bundled-resource closure selector: the entire
/// immutable embedded catalog (max 256 files, 8 MiB of source) is inspected.
const MAX_CATALOG_FILES: usize = 256;
const MAX_CATALOG_DEPTH: usize = 16;
const MAX_CATALOG_FILE_BYTES: usize = 1024 * 1024;
const MAX_CATALOG_TOTAL_BYTES: usize = 8 * 1024 * 1024;

/// Catalog-derived implicit-externs prelude: one `use <namespace>;` per host
/// namespace the compile catalog publishes. Mirrors the existing snapshot
/// prelude but derives from the supplied catalog, so parsing tolerates the same
/// implicit host externs the real compiler provides. Prelude declarations are
/// dropped before module imports are inspected.
fn catalog_prelude(catalog: &HostApiCatalog) -> String {
    let mut namespaces = BTreeSet::new();
    for function in catalog.functions() {
        if let Some((namespace, _)) = function.name.split_once("::") {
            namespaces.insert(namespace.to_string());
        }
    }
    let mut prelude = String::new();
    for namespace in namespaces {
        prelude.push_str("use ");
        prelude.push_str(&namespace);
        prelude.push_str(";\n");
    }
    prelude
}

fn scan_imports_with_prelude(
    source: &str,
    dialect: &'static dyn ParserDialect,
    prelude: &str,
) -> Result<Vec<BundleImport>, ClosedBundleError> {
    if prelude.is_empty() {
        return scan_imports(source, dialect);
    }
    let prelude_imports = scan_imports(prelude, dialect)?;
    let combined = format!("{prelude}{source}");
    let mut imports = scan_imports(&combined, dialect)?;
    imports.drain(0..prelude_imports.len());
    Ok(imports)
}

/// The bundled-resource closure selector parses with the EXISTING snapshot
/// RustScript dialect (reused, never a new one).
fn bundled_rss_dialect() -> &'static dyn ParserDialect {
    crate::runtime::module_snapshot::snapshot_parser_dialect()
}

/// Caller-supplied bounds for a closed bundle.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ClosedBundleLimits {
    pub max_files: usize,
    pub max_depth: usize,
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
}

/// Caller-supplied embedding parameters for one closed-bundle compilation.
pub(crate) struct ClosedBundleOptions<'a> {
    pub limits: ClosedBundleLimits,
    pub virtual_root: &'a Path,
    pub host_roots: &'a BTreeSet<String>,
    pub catalog: Arc<HostApiCatalog>,
    pub dialect: &'static dyn ParserDialect,
    pub entry_export: &'a str,
}

/// Fixed failure categories of the closed-bundle boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClosedBundleError {
    SourceTooLarge,
    SourceInvalid,
    ImportDenied,
    CompileFailed,
}

/// One admitted, closed bundle: the compiled program plus its exact root
/// export callable name (`None` when the root export is absent).
pub(crate) struct CompiledClosedBundle {
    pub program: rustscript_vm::Program,
    pub entry_name: Option<String>,
}

struct BundleImport {
    path: Vec<UsePathSegment>,
    clause: ImportClause,
}

/// Compile a closed, bounded RSS tree from trusted embedding-owned bytes.
/// No input path is opened or materialized on disk.
///
/// This is the ORIGINAL entry: it scans each module's imports with the
/// original no-prepended-import mode. Its algorithm, bounds, host-collision
/// and reachability checks are unchanged.
pub(crate) fn compile_closed_bundle(
    entry_path: &str,
    sources: &[(&str, &str)],
    options: ClosedBundleOptions<'_>,
) -> Result<CompiledClosedBundle, ClosedBundleError> {
    compile_closed_bundle_impl(entry_path, sources, options, false)
}

/// Bundled-resource entry: the SAME shared compiler/admission body, but each
/// module is parsed with the catalog-derived implicit-externs parse context the
/// real compiler supplies. This never grants permissions; it only lets parsing
/// accept the same host externs the shipped sources rely on. Only the immutable
/// embedded bundled route (and its catalog probe) use this.
pub(crate) fn compile_bundled_closed_bundle(
    entry_path: &str,
    sources: &[(&str, &str)],
    options: ClosedBundleOptions<'_>,
) -> Result<CompiledClosedBundle, ClosedBundleError> {
    compile_closed_bundle_impl(entry_path, sources, options, true)
}

fn compile_closed_bundle_impl(
    entry_path: &str,
    sources: &[(&str, &str)],
    options: ClosedBundleOptions<'_>,
    catalog_parse_context: bool,
) -> Result<CompiledClosedBundle, ClosedBundleError> {
    if !options.virtual_root.is_absolute() {
        return Err(ClosedBundleError::ImportDenied);
    }
    let limits = options.limits;
    let virtual_root = options.virtual_root;
    let entry_export = options.entry_export;

    if sources.len() > limits.max_files {
        return Err(ClosedBundleError::SourceTooLarge);
    }
    validate_bundle_path(entry_path, limits.max_depth)?;
    let mut total_bytes = 0usize;
    let mut bundle = BTreeMap::new();
    for (path, source) in sources {
        validate_bundle_path(path, limits.max_depth)?;
        if source.len() > limits.max_file_bytes {
            return Err(ClosedBundleError::SourceTooLarge);
        }
        total_bytes = total_bytes
            .checked_add(source.len())
            .ok_or(ClosedBundleError::SourceTooLarge)?;
        if total_bytes > limits.max_total_bytes {
            return Err(ClosedBundleError::SourceTooLarge);
        }
        if bundle
            .insert((*path).to_owned(), (*source).to_owned())
            .is_some()
        {
            return Err(ClosedBundleError::ImportDenied);
        }
    }
    let entry = bundle
        .get(entry_path)
        .ok_or(ClosedBundleError::ImportDenied)?;
    reject_host_collisions(bundle.keys(), options.host_roots)?;
    // The original entry scans modules with their own imports untouched. The
    // bundled entry additionally parses each module under the catalog-derived
    // implicit-externs parse context the real compiler supplies; the prelude
    // declarations are dropped so only module imports are admitted, and the
    // provided-tree reachability checks below are identical either way.
    let prelude = if catalog_parse_context {
        catalog_prelude(&options.catalog)
    } else {
        String::new()
    };
    let mut imports = BTreeMap::new();
    for (path, source) in &bundle {
        imports.insert(
            path.clone(),
            scan_imports_with_prelude(source, options.dialect, &prelude)?,
        );
    }
    preflight_bundle(&bundle, &imports, options.host_roots, limits.max_depth)?;

    let catalog = options.catalog;
    let mut compile_options =
        CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog));
    for (path, source) in &bundle {
        let module_path = virtual_path(virtual_root, path);
        compile_options
            .set_module_override_source(module_path.to_string_lossy().into_owned(), source);
    }
    let entry_virtual_path = virtual_path(virtual_root, entry_path);
    let analysis_path = entry_virtual_path.clone();
    let analysis_source = entry.clone();
    let analysis_options = compile_options.clone();
    let (semantic_model, compiled) = std::thread::scope(|scope| {
        let analysis = scope.spawn(move || {
            analyze_source_from_string_with_options(
                analysis_path,
                &analysis_source,
                analysis_options,
            )
        });
        let compiled = compile_source_at_path_with_flavor_and_options(
            &entry_virtual_path,
            entry,
            SourceFlavor::RustScript,
            compile_options,
        );
        let semantic_model = analysis
            .join()
            .map_err(|_| ClosedBundleError::CompileFailed)?
            .map_err(|_| ClosedBundleError::CompileFailed)?;
        let compiled = compiled.map_err(|_| ClosedBundleError::CompileFailed)?;
        Ok::<_, ClosedBundleError>((semantic_model, compiled))
    })?;
    let module_graph = semantic_model
        .module_graph()
        .ok_or(ClosedBundleError::CompileFailed)?;
    let root_module = module_graph
        .module_id_for_identity(&entry_virtual_path)
        .ok_or(ClosedBundleError::CompileFailed)?;
    let entry_name = match module_graph.symbol_for_export(root_module, entry_export) {
        Some(symbol) => {
            let mut declarations = semantic_model
                .ir()
                .functions
                .iter()
                .filter(|function| function.symbol == Some(symbol));
            let function = declarations
                .next()
                .ok_or(ClosedBundleError::CompileFailed)?;
            if declarations.next().is_some() {
                return Err(ClosedBundleError::CompileFailed);
            }
            Some(function.name.clone())
        }
        None => None,
    };
    if let Some(entry_name) = entry_name.as_deref() {
        let matching_exports = compiled
            .program
            .exported_callables
            .iter()
            .filter(|callable| callable.name.as_str() == entry_name)
            .count();
        if matching_exports != 1 {
            return Err(ClosedBundleError::CompileFailed);
        }
    }
    Ok(CompiledClosedBundle {
        program: compiled.program,
        entry_name,
    })
}

fn validate_bundle_path(path: &str, max_depth: usize) -> Result<(), ClosedBundleError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
    {
        return Err(ClosedBundleError::ImportDenied);
    }
    let components: Vec<&str> = path.split('/').collect();
    if components.len() > max_depth
        || components
            .iter()
            .any(|component| component.is_empty() || *component == "." || *component == "..")
    {
        return Err(ClosedBundleError::ImportDenied);
    }
    for (index, component) in components.iter().enumerate() {
        let name = if index + 1 == components.len() {
            component
                .strip_suffix(".rss")
                .ok_or(ClosedBundleError::ImportDenied)?
        } else {
            component
        };
        if !valid_module_identifier(name) {
            return Err(ClosedBundleError::ImportDenied);
        }
    }
    Ok(())
}

pub(crate) fn valid_module_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_alphabetic())
        && chars.all(|character| character == '_' || character.is_alphanumeric())
}

fn virtual_path(root: &Path, path: &str) -> PathBuf {
    root.join(path)
}

fn reject_host_collisions<'a>(
    paths: impl Iterator<Item = &'a String>,
    host_roots: &BTreeSet<String>,
) -> Result<(), ClosedBundleError> {
    for path in paths {
        let first = path
            .split('/')
            .next()
            .ok_or(ClosedBundleError::ImportDenied)?;
        let root = first.strip_suffix(".rss").unwrap_or(first);
        if host_roots.contains(root) {
            return Err(ClosedBundleError::ImportDenied);
        }
    }
    Ok(())
}

fn scan_imports(
    source: &str,
    dialect: &'static dyn ParserDialect,
) -> Result<Vec<BundleImport>, ClosedBundleError> {
    let ir = parse_source_with_dialect(
        source,
        dialect,
        SharedParserOptions {
            source_id: 0,
            allow_implicit_externs: true,
            allow_implicit_semicolons: false,
            enforce_mutable_bindings: false,
            import_scan_mode: true,
        },
    )
    .map_err(|_| ClosedBundleError::SourceInvalid)?;
    ir.use_declarations
        .into_iter()
        .map(|declaration| {
            if matches!(
                declaration.clause,
                ImportClause::AllPublic | ImportClause::Named(_) | ImportClause::Namespace(_)
            ) {
                Ok(BundleImport {
                    path: declaration.path,
                    clause: declaration.clause,
                })
            } else {
                Err(ClosedBundleError::ImportDenied)
            }
        })
        .collect()
}

fn preflight_bundle(
    bundle: &BTreeMap<String, String>,
    imports: &BTreeMap<String, Vec<BundleImport>>,
    host_roots: &BTreeSet<String>,
    max_depth: usize,
) -> Result<(), ClosedBundleError> {
    for (importer, imports) in imports {
        for import in imports {
            let (root, first_index) = first_import_identifier(&import.path)?;
            if first_index == 0 && host_roots.contains(root) {
                if import.path.len() == 1
                    && matches!(
                        import.clause,
                        ImportClause::AllPublic | ImportClause::Namespace(_)
                    )
                {
                    continue;
                }
                return Err(ClosedBundleError::ImportDenied);
            }
            let target = resolve_bundle_import(importer, &import.path, max_depth)?;
            if !bundle.contains_key(&target) {
                return Err(ClosedBundleError::ImportDenied);
            }
        }
    }
    Ok(())
}

fn first_import_identifier(path: &[UsePathSegment]) -> Result<(&str, usize), ClosedBundleError> {
    path.iter()
        .enumerate()
        .find_map(|(index, segment)| match segment {
            UsePathSegment::Ident(name) => Some((name.as_str(), index)),
            UsePathSegment::Self_ | UsePathSegment::Super => None,
        })
        .ok_or(ClosedBundleError::ImportDenied)
}

/// Select the bounded import closure for one chosen catalog key using the
/// EXISTING admission helpers (`validate_bundle_path` / `scan_imports` /
/// `resolve_bundle_import` and the identical host-namespace clause check). The
/// whole immutable catalog is supplied; only the selected closure is returned,
/// sorted by key. Unselected inventory-only modules are ignored; a selected
/// module that cannot be parsed or resolved is rejected.
pub(crate) fn select_catalog_closure(
    catalog: &[(&str, &str)],
    host_catalog: &HostApiCatalog,
    entry_key: &str,
    host_roots: &BTreeSet<String>,
) -> Result<Vec<String>, ClosedBundleError> {
    if catalog.len() > MAX_CATALOG_FILES {
        return Err(ClosedBundleError::SourceTooLarge);
    }
    let mut total_bytes = 0usize;
    let mut sources: BTreeMap<&str, &str> = BTreeMap::new();
    for (key, source) in catalog {
        if source.len() > MAX_CATALOG_FILE_BYTES {
            return Err(ClosedBundleError::SourceTooLarge);
        }
        total_bytes = total_bytes
            .checked_add(source.len())
            .ok_or(ClosedBundleError::SourceTooLarge)?;
        if total_bytes > MAX_CATALOG_TOTAL_BYTES {
            return Err(ClosedBundleError::SourceTooLarge);
        }
        if sources.insert(*key, *source).is_some() {
            return Err(ClosedBundleError::ImportDenied);
        }
    }
    validate_bundle_path(entry_key, MAX_CATALOG_DEPTH)?;
    sources
        .get(entry_key)
        .ok_or(ClosedBundleError::ImportDenied)?;

    let prelude = catalog_prelude(host_catalog);
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(entry_key.to_owned());
    while let Some(key) = queue.pop_front() {
        if !visited.insert(key.clone()) {
            continue;
        }
        validate_bundle_path(&key, MAX_CATALOG_DEPTH)?;
        let source = *sources
            .get(key.as_str())
            .ok_or(ClosedBundleError::ImportDenied)?;
        let module_imports = scan_imports_with_prelude(source, bundled_rss_dialect(), &prelude)?;
        for import in &module_imports {
            let (root, first_index) = first_import_identifier(&import.path)?;
            if first_index == 0 && host_roots.contains(root) {
                if import.path.len() == 1
                    && matches!(
                        import.clause,
                        ImportClause::AllPublic | ImportClause::Namespace(_)
                    )
                {
                    continue;
                }
                return Err(ClosedBundleError::ImportDenied);
            }
            let target = resolve_bundle_import(&key, &import.path, MAX_CATALOG_DEPTH)?;
            if !sources.contains_key(target.as_str()) {
                return Err(ClosedBundleError::ImportDenied);
            }
            if !visited.contains(&target) {
                queue.push_back(target);
            }
        }
    }
    let mut selected: Vec<String> = visited.iter().cloned().collect();
    selected.sort();
    Ok(selected)
}

fn resolve_bundle_import(
    importer: &str,
    segments: &[UsePathSegment],
    max_depth: usize,
) -> Result<String, ClosedBundleError> {
    if segments.is_empty() {
        return Err(ClosedBundleError::ImportDenied);
    }
    let mut resolved: Vec<&str> = importer
        .rsplit_once('/')
        .map(|(parent, _)| parent.split('/').collect())
        .unwrap_or_default();
    let mut cursor = 0usize;
    while cursor < segments.len() {
        match &segments[cursor] {
            UsePathSegment::Self_ => cursor += 1,
            UsePathSegment::Super => {
                if resolved.pop().is_none() {
                    return Err(ClosedBundleError::ImportDenied);
                }
                cursor += 1;
            }
            UsePathSegment::Ident(name) if name == "crate" => {
                return Err(ClosedBundleError::ImportDenied);
            }
            UsePathSegment::Ident(_) => break,
        }
    }
    if cursor == segments.len() {
        return Err(ClosedBundleError::ImportDenied);
    }
    let mut names = Vec::with_capacity(segments.len() - cursor);
    for segment in &segments[cursor..] {
        let name = match segment {
            UsePathSegment::Ident(name) if valid_module_identifier(name) => name.as_str(),
            UsePathSegment::Self_ => "self",
            UsePathSegment::Super => "super",
            _ => return Err(ClosedBundleError::ImportDenied),
        };
        names.push(name);
    }
    resolved.extend(names);
    let target = format!("{}.rss", resolved.join("/"));
    validate_bundle_path(&target, max_depth)?;
    Ok(target)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    struct TestDialect;

    impl ParserDialect for TestDialect {
        fn allow_let_mut_binding(&self) -> bool {
            true
        }

        fn allow_macro_calls(&self) -> bool {
            true
        }

        fn allow_plus_equal_operator(&self) -> bool {
            true
        }

        fn allow_for_in_loop(&self) -> bool {
            true
        }
    }

    static TEST_DIALECT: TestDialect = TestDialect;

    const CUSTOM_ROOT: &str = "custom_namespace";
    const CUSTOM_VIRTUAL_ROOT: &str = "/__closed_bundle_unit_root__";

    fn default_host_roots() -> BTreeSet<String> {
        ["io", "json", "bytes", "re", "jit", "math", "sqlite"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    fn custom_host_roots() -> BTreeSet<String> {
        BTreeSet::from(["json".to_owned(), CUSTOM_ROOT.to_owned()])
    }

    fn default_options(host_roots: &BTreeSet<String>) -> ClosedBundleOptions<'_> {
        ClosedBundleOptions {
            limits: ClosedBundleLimits {
                max_files: 64,
                max_depth: 16,
                max_file_bytes: 1024 * 1024,
                max_total_bytes: 4 * 1024 * 1024,
            },
            virtual_root: Path::new("/__closed_bundle_default_root__"),
            host_roots,
            catalog: rustscript_vm::standard_host_catalog(),
            dialect: &TEST_DIALECT,
            entry_export: "run",
        }
    }

    fn run_exported(program: rustscript_vm::Program, entry_name: &str) -> rustscript_vm::Value {
        let vm = rustscript_vm::Vm::try_new(program).expect("construct vm");
        run_vm_exported(vm, entry_name)
    }

    fn run_vm_exported(mut vm: rustscript_vm::Vm, entry_name: &str) -> rustscript_vm::Value {
        vm.run().expect("run root frame");
        let callable = vm
            .resolve_exported_callable(entry_name)
            .expect("resolve exported callable");
        let mut invocation = vm
            .start_invocation(callable, Vec::new())
            .expect("start invocation");
        loop {
            match invocation.poll_next().expect("poll invocation") {
                rustscript_vm::InvocationPoll::Pending => {
                    std::thread::sleep(std::time::Duration::from_millis(1))
                }
                rustscript_vm::InvocationPoll::Ready(Some(Ok(
                    rustscript_vm::InvocationItem::Complete(value),
                ))) => return value,
                other => panic!("unexpected invocation item: {other:?}"),
            }
        }
    }

    fn expect_denied(
        result: Result<CompiledClosedBundle, ClosedBundleError>,
        reason: &str,
    ) -> ClosedBundleError {
        match result {
            Err(error) => error,
            Ok(_) => panic!("{reason}"),
        }
    }

    #[test]
    fn supplied_smaller_file_limit_is_honored() {
        let body = "pub fn run() -> int { 1 }";
        let sources = [("main.rss", body)];
        let host_roots = default_host_roots();
        let mut options = default_options(&host_roots);
        options.limits.max_file_bytes = 4;
        let error = expect_denied(
            compile_closed_bundle("main.rss", &sources, options),
            "supplied per-file limit must reject the oversized source",
        );
        assert_eq!(error, ClosedBundleError::SourceTooLarge);
    }

    #[test]
    fn supplied_smaller_file_count_limit_is_honored() {
        let sources = [
            ("main.rss", "pub fn run() -> int { 1 }"),
            ("extra.rss", "pub fn value() -> int { 2 }"),
        ];
        let host_roots = default_host_roots();
        let mut options = default_options(&host_roots);
        options.limits.max_files = 1;
        let error = expect_denied(
            compile_closed_bundle("main.rss", &sources, options),
            "supplied file-count limit must reject the extra source",
        );
        assert_eq!(error, ClosedBundleError::SourceTooLarge);
    }

    #[test]
    fn supplied_smaller_total_bytes_limit_is_honored() {
        let body = "pub fn run() -> int { 1 }";
        let sources = [("main.rss", body), ("extra.rss", body)];
        let host_roots = default_host_roots();
        let mut options = default_options(&host_roots);
        options.limits.max_total_bytes = body.len() + 1;
        let error = expect_denied(
            compile_closed_bundle("main.rss", &sources, options),
            "supplied aggregate byte limit must reject the combined bytes",
        );
        assert_eq!(error, ClosedBundleError::SourceTooLarge);
    }

    #[test]
    fn supplied_smaller_depth_limit_is_honored() {
        let body = "pub fn run() -> int { 1 }";
        let sources = [("a/b/main.rss", body)];
        let host_roots = default_host_roots();
        let mut options = default_options(&host_roots);
        options.limits.max_depth = 2;
        let error = expect_denied(
            compile_closed_bundle("a/b/main.rss", &sources, options),
            "supplied depth limit must reject the deeper path",
        );
        assert_eq!(error, ClosedBundleError::ImportDenied);
    }

    #[test]
    fn supplied_alternate_virtual_root_compiles_and_runs() {
        let source = "pub fn run() -> int { 7 }";
        let sources = [("main.rss", source)];
        let host_roots = default_host_roots();
        let mut options = default_options(&host_roots);
        options.virtual_root = Path::new(CUSTOM_VIRTUAL_ROOT);
        let compiled = compile_closed_bundle("main.rss", &sources, options)
            .expect("alternate virtual root must compile");
        let entry_name = compiled.entry_name.expect("root run must be selected");
        let value = run_exported(compiled.program, &entry_name);
        assert_eq!(value, rustscript_vm::Value::Int(7));
    }

    fn ping_descriptor() -> rustscript_vm::HostFunctionDescriptor {
        crate::runtime::host_compose::static_stack_descriptor(
            rustscript_vm::HostFunctionSchema::with_return(
                "custom_namespace::ping",
                vec![rustscript_vm::HostParamSchema::value(
                    "value",
                    rustscript_vm::HostTypeSchema::Int,
                )],
                rustscript_vm::HostTypeSchema::Int,
            ),
            |_vm, args| {
                let [rustscript_vm::Value::Int(value)] = args else {
                    panic!("native adapter requires its declared int argument");
                };
                Ok(rustscript_vm::CallOutcome::Return(
                    rustscript_vm::CallReturn::One(rustscript_vm::Value::Int(value + 1)),
                ))
            },
        )
    }

    fn bundled_probe_host_roots() -> BTreeSet<String> {
        let mut host_roots: BTreeSet<String> =
            ["json", "bytes"].into_iter().map(str::to_owned).collect();
        for function in crate::runtime::agent_host::agent_host_catalog().functions() {
            if let Some((namespace, _)) = function.name.split_once("::") {
                host_roots.insert(namespace.to_owned());
            }
        }
        host_roots
    }

    fn probe_closure(entry: &str) -> Vec<String> {
        select_catalog_closure(
            crate::bundled_rss_sources(),
            crate::runtime::agent_host::agent_host_catalog().as_ref(),
            entry,
            &bundled_probe_host_roots(),
        )
        .unwrap_or_else(|error| panic!("closure for {entry}: {error:?}"))
    }

    fn probe_compile(entry: &str, export: &str) -> CompiledClosedBundle {
        let closure = probe_closure(entry);
        let sources: Vec<(&str, &str)> = closure
            .iter()
            .map(|key| {
                (
                    key.as_str(),
                    *crate::bundled_rss_sources()
                        .iter()
                        .find(|(k, _)| k == key)
                        .map(|(_, s)| s)
                        .expect("catalog key"),
                )
            })
            .collect();
        let host_roots = bundled_probe_host_roots();
        compile_bundled_closed_bundle(
            entry,
            &sources,
            ClosedBundleOptions {
                limits: ClosedBundleLimits {
                    max_files: 256,
                    max_depth: 16,
                    max_file_bytes: crate::runtime::rss_runner::MAX_AGENT_SOURCE_BYTES,
                    max_total_bytes: 8 * 1024 * 1024,
                },
                virtual_root: Path::new("/__rustscript_agent_bundled_rss__"),
                host_roots: &host_roots,
                catalog: crate::runtime::agent_host::agent_host_catalog(),
                dialect: bundled_rss_dialect(),
                entry_export: export,
            },
        )
        .unwrap_or_else(|error| panic!("compile {entry} as {export}: {error:?}"))
    }

    #[test]
    fn catalog_closure_ignores_unselected_inventory_but_rejects_it_when_selected() {
        // `rss/storage/import-test.rss` is inventory-only: selecting the storage
        // entry must succeed without it, and it must be absent from the closure.
        let storage = probe_closure("rss/storage/main.rss");
        assert!(
            !storage
                .iter()
                .any(|key| key == "rss/storage/import-test.rss")
        );
        probe_compile("rss/storage/main.rss", "run");

        // Selecting the invalid import-test module in its own right is rejected.
        let error = select_catalog_closure(
            crate::bundled_rss_sources(),
            crate::runtime::agent_host::agent_host_catalog().as_ref(),
            "rss/storage/import-test.rss",
            &bundled_probe_host_roots(),
        )
        .expect_err("invalid import-test module must be rejected when selected");
        assert_eq!(error, ClosedBundleError::ImportDenied);
    }

    #[test]
    fn catalog_closure_rejects_unknown_entry_and_is_sorted() {
        let error = select_catalog_closure(
            crate::bundled_rss_sources(),
            crate::runtime::agent_host::agent_host_catalog().as_ref(),
            "rss/does/not/exist.rss",
            &bundled_probe_host_roots(),
        )
        .expect_err("unknown entry must be rejected");
        assert_eq!(error, ClosedBundleError::ImportDenied);

        let closure = probe_closure("rss/llm/provider_dispatch.rss");
        assert!(closure.windows(2).all(|pair| pair[0] < pair[1]));
        probe_compile("rss/llm/provider_dispatch.rss", "dispatch");
    }

    #[test]
    fn supplied_alternate_catalog_namespace_binds_and_runs() {
        let source = r#"use custom_namespace;
pub fn run() -> int { custom_namespace::ping(41) }
"#;
        let sources = [("main.rss", source)];
        let host_roots = custom_host_roots();
        let mut builder = rustscript_vm::HostApiBuilder::new();
        builder.function(ping_descriptor().schema);
        let catalog = Arc::new(builder.build().expect("build custom catalog"));
        let mut options = default_options(&host_roots);
        options.catalog = Arc::clone(&catalog);
        let compiled = compile_closed_bundle("main.rss", &sources, options)
            .expect("alternate catalog namespace must be admitted");
        let entry_name = compiled.entry_name.expect("root run must be selected");
        let module = rustscript_vm::HostModuleDescriptor {
            name: CUSTOM_ROOT,
            functions: &[ping_descriptor],
            resources: &[],
        };
        let mut registry = rustscript_vm::HostFunctionRegistry::restricted();
        module
            .install_from_catalog(&mut registry, catalog.as_ref())
            .expect("install the supplied catalog's native descriptor");
        let mut vm = rustscript_vm::Vm::try_new(compiled.program).expect("construct vm");
        registry
            .bind_vm_cached(&mut vm)
            .expect("bind only the registered custom host");
        let value = run_vm_exported(vm, &entry_name);
        assert_eq!(value, rustscript_vm::Value::Int(42));
    }

    #[test]
    fn supplied_entry_export_selects_exact_root_symbol_not_a_sibling_run() {
        let source = r#"pub fn run() -> int { 1 }
pub fn alt() -> int { 9 }
"#;
        let sources = [("main.rss", source)];
        let host_roots = default_host_roots();
        let mut options = default_options(&host_roots);
        options.entry_export = "alt";
        let compiled = compile_closed_bundle("main.rss", &sources, options)
            .expect("bundle with a sibling run export must compile");
        let entry_name = compiled
            .entry_name
            .expect("exact entry export must be selected");
        let value = run_exported(compiled.program, &entry_name);
        assert_eq!(value, rustscript_vm::Value::Int(9));
    }
}
