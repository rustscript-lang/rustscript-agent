use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustscript_vm::{
    CompileSourceFileOptions, ImportClause, SharedParserOptions, SourceFlavor, UsePathSegment,
    compile_source_at_path_with_flavor_and_options, parse_source_with_dialect,
};

use super::{AUTH_ENTRY_PARSER_DIALECT, AuthEntryError, AuthEntryRunner, MAX_AGENT_SOURCE_BYTES};
use crate::auth::host::{auth_host_catalog, auth_host_module};

const MAX_BUNDLE_FILES: usize = 64;
const MAX_BUNDLE_DEPTH: usize = 16;
const MAX_BUNDLE_SOURCE_BYTES: usize = 4 * MAX_AGENT_SOURCE_BYTES;
const VIRTUAL_BUNDLE_ROOT: &str = "/__rustscript_agent_auth_bundle__";
const JSON_ROOT: &str = "json";

struct BundleImport {
    path: Vec<UsePathSegment>,
    clause: ImportClause,
}

impl AuthEntryRunner {
    /// Compile a closed, bounded RSS tree from trusted embedding-owned bytes.
    /// No input path is opened or materialized on disk.
    pub fn from_bundle(entry_path: &str, sources: &[(&str, &str)]) -> Result<Self, AuthEntryError> {
        if sources.len() > MAX_BUNDLE_FILES {
            return Err(AuthEntryError::SourceTooLarge);
        }
        validate_bundle_path(entry_path)?;
        let mut total_bytes = 0usize;
        let mut bundle = BTreeMap::new();
        for (path, source) in sources {
            validate_bundle_path(path)?;
            if source.len() > MAX_AGENT_SOURCE_BYTES {
                return Err(AuthEntryError::SourceTooLarge);
            }
            total_bytes = total_bytes
                .checked_add(source.len())
                .ok_or(AuthEntryError::SourceTooLarge)?;
            if total_bytes > MAX_BUNDLE_SOURCE_BYTES {
                return Err(AuthEntryError::SourceTooLarge);
            }
            if bundle
                .insert((*path).to_owned(), (*source).to_owned())
                .is_some()
            {
                return Err(AuthEntryError::ImportDenied);
            }
        }
        let entry = bundle.get(entry_path).ok_or(AuthEntryError::ImportDenied)?;
        let host_roots = admitted_host_roots();
        reject_host_collisions(bundle.keys(), &host_roots)?;
        let mut imports = BTreeMap::new();
        for (path, source) in &bundle {
            imports.insert(path.clone(), scan_imports(source)?);
        }
        preflight_bundle(&bundle, &imports, &host_roots)?;

        let catalog = auth_host_catalog();
        let mut options =
            CompileSourceFileOptions::default().with_host_api_catalog(Arc::clone(&catalog));
        for (path, source) in &bundle {
            let virtual_path = virtual_path(path);
            options.set_module_override_source(virtual_path.to_string_lossy().into_owned(), source);
        }
        let entry_virtual_path = virtual_path(entry_path);
        let compiled = compile_source_at_path_with_flavor_and_options(
            &entry_virtual_path,
            entry,
            SourceFlavor::RustScript,
            options,
        )
        .map_err(|_| AuthEntryError::CompileFailed)?;
        Ok(Self {
            program: compiled.program,
            catalog,
            bundle_json_encode: true,
        })
    }
}

fn validate_bundle_path(path: &str) -> Result<(), AuthEntryError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
    {
        return Err(AuthEntryError::ImportDenied);
    }
    let components: Vec<&str> = path.split('/').collect();
    if components.len() > MAX_BUNDLE_DEPTH
        || components
            .iter()
            .any(|component| component.is_empty() || *component == "." || *component == "..")
    {
        return Err(AuthEntryError::ImportDenied);
    }
    for (index, component) in components.iter().enumerate() {
        let name = if index + 1 == components.len() {
            component
                .strip_suffix(".rss")
                .ok_or(AuthEntryError::ImportDenied)?
        } else {
            component
        };
        if !valid_module_identifier(name) {
            return Err(AuthEntryError::ImportDenied);
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

fn virtual_path(path: &str) -> PathBuf {
    Path::new(VIRTUAL_BUNDLE_ROOT).join(path)
}

fn admitted_host_roots() -> BTreeSet<String> {
    let mut roots = BTreeSet::new();
    for descriptor in auth_host_module().descriptors() {
        if let Some((root, _)) = descriptor.schema.name.split_once("::") {
            roots.insert(root.to_owned());
        }
    }
    roots.insert(JSON_ROOT.to_owned());
    roots
}

fn reject_host_collisions<'a>(
    paths: impl Iterator<Item = &'a String>,
    host_roots: &BTreeSet<String>,
) -> Result<(), AuthEntryError> {
    for path in paths {
        let first = path.split('/').next().ok_or(AuthEntryError::ImportDenied)?;
        let root = first.strip_suffix(".rss").unwrap_or(first);
        if host_roots.contains(root) {
            return Err(AuthEntryError::ImportDenied);
        }
    }
    Ok(())
}

fn scan_imports(source: &str) -> Result<Vec<BundleImport>, AuthEntryError> {
    let ir = parse_source_with_dialect(
        source,
        &AUTH_ENTRY_PARSER_DIALECT,
        SharedParserOptions {
            source_id: 0,
            allow_implicit_externs: true,
            allow_implicit_semicolons: false,
            enforce_mutable_bindings: false,
            import_scan_mode: true,
        },
    )
    .map_err(|_| AuthEntryError::SourceInvalid)?;
    ir.use_declarations
        .into_iter()
        .map(|declaration| {
            if matches!(
                declaration.clause,
                ImportClause::AllPublic | ImportClause::Namespace(_)
            ) {
                Ok(BundleImport {
                    path: declaration.path,
                    clause: declaration.clause,
                })
            } else {
                Err(AuthEntryError::ImportDenied)
            }
        })
        .collect()
}

fn preflight_bundle(
    bundle: &BTreeMap<String, String>,
    imports: &BTreeMap<String, Vec<BundleImport>>,
    host_roots: &BTreeSet<String>,
) -> Result<(), AuthEntryError> {
    for (importer, imports) in imports {
        for import in imports {
            let (root, first_index) = first_import_identifier(&import.path)?;
            if host_roots.contains(root) {
                if first_index == 0
                    && import.path.len() == 1
                    && matches!(
                        import.clause,
                        ImportClause::AllPublic | ImportClause::Namespace(_)
                    )
                {
                    continue;
                }
                return Err(AuthEntryError::ImportDenied);
            }
            let target = resolve_bundle_import(importer, &import.path)?;
            if !bundle.contains_key(&target) {
                return Err(AuthEntryError::ImportDenied);
            }
        }
    }
    Ok(())
}

fn first_import_identifier(path: &[UsePathSegment]) -> Result<(&str, usize), AuthEntryError> {
    path.iter()
        .enumerate()
        .find_map(|(index, segment)| match segment {
            UsePathSegment::Ident(name) => Some((name.as_str(), index)),
            UsePathSegment::Self_ | UsePathSegment::Super => None,
        })
        .ok_or(AuthEntryError::ImportDenied)
}

fn resolve_bundle_import(
    importer: &str,
    segments: &[UsePathSegment],
) -> Result<String, AuthEntryError> {
    if segments.is_empty() {
        return Err(AuthEntryError::ImportDenied);
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
                    return Err(AuthEntryError::ImportDenied);
                }
                cursor += 1;
            }
            UsePathSegment::Ident(name) if name == "crate" => {
                return Err(AuthEntryError::ImportDenied);
            }
            UsePathSegment::Ident(_) => break,
        }
    }
    if cursor == segments.len() {
        return Err(AuthEntryError::ImportDenied);
    }
    let mut names = Vec::with_capacity(segments.len() - cursor);
    for segment in &segments[cursor..] {
        let name = match segment {
            UsePathSegment::Ident(name) if valid_module_identifier(name) => name.as_str(),
            UsePathSegment::Self_ => "self",
            UsePathSegment::Super => "super",
            _ => return Err(AuthEntryError::ImportDenied),
        };
        names.push(name);
    }
    resolved.extend(names);
    let target = format!("{}.rss", resolved.join("/"));
    validate_bundle_path(&target)?;
    Ok(target)
}
