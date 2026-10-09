//! Closed, bounded RSS bundle compilation.
//!
//! This module owns the generic native compile/admission primitive. It parses
//! every supplied source with a caller-supplied dialect, admits only a closed
//! in-memory import graph bounded by caller-supplied limits, and resolves the
//! exact root export through Core's module graph. It carries no auth workflow,
//! no registry grants, no global cache, and no serialization.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustscript_vm::{
    CompileSourceFileOptions, HostApiCatalog, ImportClause, ParserDialect, SharedParserOptions,
    SourceFlavor, UsePathSegment, analyze_source_from_string_with_options,
    compile_source_at_path_with_flavor_and_options, parse_source_with_dialect,
};

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
pub(crate) fn compile_closed_bundle(
    entry_path: &str,
    sources: &[(&str, &str)],
    options: ClosedBundleOptions<'_>,
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
    let mut imports = BTreeMap::new();
    for (path, source) in &bundle {
        imports.insert(path.clone(), scan_imports(source, options.dialect)?);
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

fn valid_module_identifier(name: &str) -> bool {
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

    // Generic RustScript dialect replica for focused unit tests. This keeps the
    // tests independent of any auth-owned dialect while exercising the same
    // native parse/admission/compile/Vm primitive.
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

    // Supplied alternate catalog/namespace root that the DEFAULT scaffold must
    // not know about.
    const CUSTOM_ROOT: &str = "custom_namespace";
    const CUSTOM_VIRTUAL_ROOT: &str = "/__closed_bundle_unit_root__";

    fn default_host_roots() -> BTreeSet<String> {
        // Root names the builtin HostApiBuilder admits by default, matching the
        // standard catalog vocabulary.
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
        let mut vm = rustscript_vm::Vm::try_new(program).expect("construct vm");
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
        // The scaffold must fail to resolve the entry under the supplied
        // virtual root and therefore cannot produce a runnable bundle.
        let mut options = default_options(&host_roots);
        options.virtual_root = Path::new(CUSTOM_VIRTUAL_ROOT);
        let compiled = compile_closed_bundle("main.rss", &sources, options)
            .expect("alternate virtual root must compile");
        let entry_name = compiled.entry_name.expect("root run must be selected");
        let value = run_exported(compiled.program, &entry_name);
        assert_eq!(value, rustscript_vm::Value::Int(7));
    }

    #[test]
    fn supplied_alternate_catalog_namespace_binds_and_runs() {
        let source = r#"use custom_namespace;
pub fn run() -> int { 1 }
"#;
        let sources = [("main.rss", source)];
        let host_roots = custom_host_roots();
        let mut catalog = rustscript_vm::HostApiBuilder::new();
        catalog.function(rustscript_vm::HostFunctionSchema::new(
            "custom_namespace::ping",
            Vec::new(),
        ));
        let mut options = default_options(&host_roots);
        options.catalog = Arc::new(catalog.build().expect("build custom catalog"));
        // The supplied alternate namespace root and catalog must both be
        // admitted so the entry compiles against the caller's catalog.
        let compiled = compile_closed_bundle("main.rss", &sources, options)
            .expect("alternate catalog namespace must be admitted");
        let entry_name = compiled.entry_name.expect("root run must be selected");
        let value = run_exported(compiled.program, &entry_name);
        assert_eq!(value, rustscript_vm::Value::Int(1));
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
        // The scaffold resolves "run"; the genuinely honored entry_export must
        // resolve "alt" instead.
        assert_eq!(entry_name, "alt");
        let value = run_exported(compiled.program, &entry_name);
        assert_eq!(value, rustscript_vm::Value::Int(9));
    }
}
