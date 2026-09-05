//! Immutable module-tree snapshot for RSS `from_file` compilation.
//!
//! The snapshot owns every regular `.rss` file under the allowed module root
//! (the nearest ancestor directory named `rss`, or the entry file's parent)
//! plus the entry's relative path and digest. Relpaths and file bytes are
//! length-prefixed into SHA-256. Compilation materializes this owned snapshot
//! into an isolated sandbox; the compiler never re-reads the original live
//! files.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
use std::cell::Cell;

use rustscript_vm::{
    ParserDialect, SharedParserOptions, UsePathSegment, parse_source_with_dialect,
};

use crate::capabilities::sha256_hex;

use super::agent_host::agent_host_catalog;
use super::rss_runner::{AgentError, MAX_AGENT_SOURCE_BYTES, Result};

const MAX_TREE_FILES: usize = 256;
const MAX_TREE_DEPTH: usize = 16;
const MAX_TREE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TREE_NODES: usize = 1024;
const COMPILE_SANDBOX_PREFIX: &str = "rss-compile-sandbox-";
const SANDBOX_TREE_DIR: &str = "tree";
const SANDBOX_PAD_DIR: &str = "p";
const SANDBOX_PAD_DEPTH: usize = MAX_TREE_DEPTH + 1;
static SANDBOX_SEQ: AtomicU64 = AtomicU64::new(0);

struct SnapshotParserDialect;

impl ParserDialect for SnapshotParserDialect {
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

static SNAPSHOT_PARSER_DIALECT: SnapshotParserDialect = SnapshotParserDialect;

fn snapshot_parser_prelude() -> &'static str {
    static PRELUDE: OnceLock<String> = OnceLock::new();
    PRELUDE
        .get_or_init(|| {
            let mut namespaces = BTreeSet::new();
            for function in agent_host_catalog().functions() {
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
        })
        .as_str()
}

/// Owned module-tree bytes used for digesting and isolated compilation.
#[derive(Debug)]
pub struct ModuleSnapshot {
    files: Vec<(String, Vec<u8>)>,
    entry_rel: String,
    digest: String,
}

impl ModuleSnapshot {
    pub fn digest(&self) -> &str {
        &self.digest
    }

    #[cfg(test)]
    pub(crate) fn entry_rel(&self) -> &str {
        &self.entry_rel
    }

    pub(crate) fn files(&self) -> &[(String, Vec<u8>)] {
        &self.files
    }

    pub(crate) fn total_source_bytes(&self) -> usize {
        self.files.iter().map(|(_, bytes)| bytes.len()).sum()
    }

    pub(crate) fn entry_source(&self) -> Result<&str> {
        let bytes = self
            .files
            .iter()
            .find(|(rel, _)| rel == &self.entry_rel)
            .map(|(_, bytes)| bytes.as_slice())
            .ok_or_else(|| tree_error("module compile sandbox failed"))?;
        std::str::from_utf8(bytes).map_err(|_| tree_error("module tree file is not valid UTF-8"))
    }

    /// Copies snapshot bytes into a unique mode-0700 sandbox. Dropping the
    /// returned guard deletes the tree on success, error, and panic.
    pub fn materialize(&self) -> Result<MaterializedSnapshot> {
        materialize_snapshot(self)
    }
}

/// Private sandbox holding one materialized snapshot. Removes the directory
/// in `Drop`.
pub struct MaterializedSnapshot {
    sandbox: PathBuf,
    allowed_root: PathBuf,
    entry: PathBuf,
}

impl MaterializedSnapshot {
    pub fn sandbox(&self) -> &Path {
        &self.sandbox
    }

    #[cfg(test)]
    pub(crate) fn allowed_root(&self) -> &Path {
        &self.allowed_root
    }

    pub fn entry(&self) -> &Path {
        &self.entry
    }

    pub(crate) fn override_source_keys(&self, rel: &str) -> Vec<String> {
        let dest = self
            .allowed_root
            .join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        let mut keys = vec![
            dest.to_string_lossy().replace('\\', "/"),
            rel.replace('\\', "/"),
        ];
        if let Ok(canonical) = dest.canonicalize() {
            keys.push(canonical.to_string_lossy().replace('\\', "/"));
        }
        keys
    }
}

impl Drop for MaterializedSnapshot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.sandbox);
    }
}

#[cfg(test)]
thread_local! {
    static AFTER_OPEN_HOOK: Cell<Option<fn(&Path)>> = const { Cell::new(None) };
}

/// Test-only hook invoked after a regular file is opened and before its bytes
/// are read, so TOCTOU grow/replacement cases can be driven deterministically.
#[cfg(test)]
pub fn set_after_open_hook(hook: Option<fn(&Path)>) {
    AFTER_OPEN_HOOK.with(|cell| cell.set(hook));
}

pub fn module_tree_digest(entry: &Path) -> Result<String> {
    Ok(capture_module_snapshot(entry)?.digest)
}

pub fn capture_module_snapshot(entry: &Path) -> Result<ModuleSnapshot> {
    let root = module_tree_root(entry)?;
    let mut files = Vec::new();
    let mut total_bytes = 0usize;
    let mut nodes = 1usize;
    walk_dir(&root, &root, 0, &mut files, &mut total_bytes, &mut nodes)?;
    files.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    assert_imports_stay_in_root(&root, &files)?;
    let entry_rel = relative_posix(&root, entry)?;
    assert_safe_rel(&entry_rel)?;
    for (rel, _) in &files {
        assert_safe_rel(rel)?;
    }
    let mut material = Vec::new();
    for (rel, bytes) in &files {
        material.extend_from_slice(&(rel.len() as u64).to_le_bytes());
        material.extend_from_slice(rel.as_bytes());
        material.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        material.extend_from_slice(bytes);
    }
    material.extend_from_slice(&(entry_rel.len() as u64).to_le_bytes());
    material.extend_from_slice(entry_rel.as_bytes());
    Ok(ModuleSnapshot {
        files,
        entry_rel,
        digest: sha256_hex(&material),
    })
}

pub fn module_tree_root(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| tree_error("module tree walk failed"))?;
    let mut current = parent;
    loop {
        if current.file_name().and_then(|name| name.to_str()) == Some("rss") {
            return Ok(current.to_path_buf());
        }
        match current.parent() {
            Some(next) if next != current => current = next,
            _ => return Ok(parent.to_path_buf()),
        }
    }
}

fn relative_posix(root: &Path, file: &Path) -> Result<String> {
    let relative = file
        .strip_prefix(root)
        .map_err(|_| tree_error("module tree walk failed"))?;
    let mut out = String::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or_else(|| tree_error("module tree file is not valid UTF-8"))?;
                if !out.is_empty() {
                    out.push('/');
                }
                out.push_str(part);
            }
            _ => return Err(tree_error("module tree walk failed")),
        }
    }
    Ok(out)
}

fn walk_dir(
    root: &Path,
    path: &Path,
    depth: usize,
    files: &mut Vec<(String, Vec<u8>)>,
    total_bytes: &mut usize,
    nodes: &mut usize,
) -> Result<()> {
    if depth > MAX_TREE_DEPTH {
        return Err(tree_error("module tree exceeds the depth bound"));
    }
    reject_symlink(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| tree_error("module tree walk failed"))?;
    if metadata.is_dir() {
        open_directory_nofollow(path)?;
        let entries = fs::read_dir(path).map_err(|_| tree_error("module tree walk failed"))?;
        let mut children = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| tree_error("module tree walk failed"))?;
            *nodes = nodes
                .checked_add(1)
                .ok_or_else(|| tree_error("module tree exceeds the entry count bound"))?;
            if *nodes > MAX_TREE_NODES {
                return Err(tree_error("module tree exceeds the entry count bound"));
            }
            children.push(entry.path());
        }
        children.sort();
        reject_symlink(path)?;
        for child in children {
            walk_dir(
                root,
                &child,
                depth.saturating_add(1),
                files,
                total_bytes,
                nodes,
            )?;
        }
        return Ok(());
    }
    if !metadata.is_file() {
        return Err(tree_error("module tree walk failed"));
    }
    if path.extension().and_then(|ext| ext.to_str()) != Some("rss") {
        return Ok(());
    }
    if files.len() >= MAX_TREE_FILES {
        return Err(tree_error("module tree exceeds the file count bound"));
    }
    let bytes = read_regular_file_capped(path)?;
    let next_total = total_bytes
        .checked_add(bytes.len())
        .ok_or_else(|| tree_error("module tree exceeds the byte bound"))?;
    if next_total > MAX_TREE_BYTES {
        return Err(tree_error("module tree exceeds the byte bound"));
    }
    *total_bytes = next_total;
    files.push((relative_posix(root, path)?, bytes));
    Ok(())
}

fn read_regular_file_capped(path: &Path) -> Result<Vec<u8>> {
    reject_symlink(path)?;
    let mut file = open_regular_nofollow(path)?;
    let meta = file
        .metadata()
        .map_err(|_| tree_error("module tree walk failed"))?;
    if !meta.is_file() {
        return Err(tree_error("module tree walk failed"));
    }
    let limit = meta.len();
    if limit > MAX_AGENT_SOURCE_BYTES as u64 {
        return Err(AgentError::Compile(format!(
            "agent source exceeds {} bytes",
            MAX_AGENT_SOURCE_BYTES
        )));
    }
    invoke_after_open(path);
    let mut reader = Read::take(&mut file, limit.saturating_add(1));
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| tree_error("module tree walk failed"))?;
    if bytes.len() as u64 != limit {
        return Err(tree_error("module file size changed during snapshot"));
    }
    let after = file
        .metadata()
        .map_err(|_| tree_error("module tree walk failed"))?;
    if after.len() != limit || !after.is_file() {
        return Err(tree_error("module file size changed during snapshot"));
    }
    reject_symlink(path)?;
    if std::str::from_utf8(&bytes).is_err() {
        return Err(tree_error("module tree file is not valid UTF-8"));
    }
    Ok(bytes)
}

fn open_regular_nofollow(path: &Path) -> Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(map_open_error)?;
        let meta = file
            .metadata()
            .map_err(|_| tree_error("module tree walk failed"))?;
        if !meta.is_file() {
            return Err(tree_error("module tree walk failed"));
        }
        Ok(file)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(map_open_error)?;
        let meta = file
            .metadata()
            .map_err(|_| tree_error("module tree walk failed"))?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(tree_error("module tree contains a symlink"));
        }
        if !meta.is_file() {
            return Err(tree_error("module tree walk failed"));
        }
        Ok(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        reject_symlink(path)?;
        let file = File::open(path).map_err(|_| tree_error("module tree walk failed"))?;
        let meta = file
            .metadata()
            .map_err(|_| tree_error("module tree walk failed"))?;
        if !meta.is_file() {
            return Err(tree_error("module tree walk failed"));
        }
        reject_symlink(path)?;
        Ok(file)
    }
}

fn open_directory_nofollow(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let _file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(map_open_error)?;
        Ok(())
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .map_err(map_open_error)?;
        let meta = file
            .metadata()
            .map_err(|_| tree_error("module tree walk failed"))?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(tree_error("module tree contains a symlink"));
        }
        if !meta.is_dir() {
            return Err(tree_error("module tree walk failed"));
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        reject_symlink(path)?;
        let meta = fs::metadata(path).map_err(|_| tree_error("module tree walk failed"))?;
        if !meta.is_dir() {
            return Err(tree_error("module tree walk failed"));
        }
        reject_symlink(path)?;
        Ok(())
    }
}

fn map_open_error(error: io::Error) -> AgentError {
    #[cfg(unix)]
    {
        if error.raw_os_error() == Some(libc::ELOOP) {
            return tree_error("module tree contains a symlink");
        }
    }
    let _ = error;
    tree_error("module tree walk failed")
}

fn reject_symlink(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(|_| tree_error("module tree walk failed"))?;
    if meta.file_type().is_symlink() {
        return Err(tree_error("module tree contains a symlink"));
    }
    Ok(())
}

#[cfg(test)]
fn invoke_after_open(path: &Path) {
    AFTER_OPEN_HOOK.with(|cell| {
        if let Some(hook) = cell.get() {
            hook(path);
        }
    });
}

#[cfg(not(test))]
fn invoke_after_open(_path: &Path) {}

fn assert_imports_stay_in_root(_root: &Path, files: &[(String, Vec<u8>)]) -> Result<()> {
    for (rel, bytes) in files {
        let source = std::str::from_utf8(bytes)
            .map_err(|_| tree_error("module tree file is not valid UTF-8"))?;
        let declarations = scan_use_declarations(source)?;
        let parent = parent_rel(rel);
        for declaration in declarations {
            match resolve_use_path(parent, &declaration)? {
                ResolvedImport::File => {}
                ResolvedImport::Escape => {
                    return Err(tree_error("module import escapes the allowed root"));
                }
            }
        }
    }
    Ok(())
}

fn scan_use_declarations(source: &str) -> Result<Vec<Vec<UsePathSegment>>> {
    let mut scan_source = String::with_capacity(snapshot_parser_prelude().len() + source.len());
    scan_source.push_str(snapshot_parser_prelude());
    scan_source.push_str(source);
    let ir = parse_source_with_dialect(
        &scan_source,
        &SNAPSHOT_PARSER_DIALECT,
        SharedParserOptions {
            source_id: 0,
            allow_implicit_externs: true,
            allow_implicit_semicolons: false,
            enforce_mutable_bindings: false,
            import_scan_mode: true,
        },
    )
    .map_err(|error| AgentError::Compile(error.to_string()))?;
    Ok(ir
        .use_declarations
        .into_iter()
        .map(|declaration| declaration.path)
        .collect())
}

enum ResolvedImport {
    File,
    Escape,
}

fn parent_rel(file_rel: &str) -> &str {
    match file_rel.rfind('/') {
        Some(index) => &file_rel[..index],
        None => "",
    }
}

fn resolve_use_path(parent: &str, segments: &[UsePathSegment]) -> Result<ResolvedImport> {
    let spec = use_segments_to_spec(segments)?;
    if spec.starts_with('/') || spec.starts_with('\\') {
        return Ok(ResolvedImport::Escape);
    }
    match join_rel(parent, &spec) {
        None => Ok(ResolvedImport::Escape),
        Some(_) => Ok(ResolvedImport::File),
    }
}

/// Mirrors the pinned compiler's `use_path_to_spec` rules after the real
/// parser has produced structured path segments. Leading `self`/`super`
/// segments are qualifiers; later occurrences are literal file segments.
fn use_segments_to_spec(segments: &[UsePathSegment]) -> Result<String> {
    if segments.is_empty() {
        return Err(tree_error("module import is malformed"));
    }
    let mut prefix = Vec::<&str>::new();
    let mut cursor = 0usize;
    let mut explicit_self = false;
    while cursor < segments.len() {
        match &segments[cursor] {
            UsePathSegment::Self_ => {
                explicit_self = true;
                cursor += 1;
            }
            UsePathSegment::Super => {
                prefix.push("..");
                cursor += 1;
            }
            UsePathSegment::Ident(name) if name == "crate" => {
                return Err(tree_error("crate imports are not supported"));
            }
            UsePathSegment::Ident(_) => break,
        }
    }
    if cursor >= segments.len() {
        return Err(tree_error("module import is malformed"));
    }
    for segment in &segments[cursor..] {
        match segment {
            UsePathSegment::Ident(name) => prefix.push(name.as_str()),
            UsePathSegment::Self_ => prefix.push("self"),
            UsePathSegment::Super => prefix.push("super"),
        }
    }
    let mut spec = prefix.join("/");
    if spec.is_empty() {
        return Err(tree_error("module import is malformed"));
    }
    if explicit_self && !spec.starts_with("../") {
        spec = format!("./{spec}");
    }
    if !spec.ends_with(".rss") {
        spec.push_str(".rss");
    }
    Ok(spec)
}

fn join_rel(parent: &str, spec: &str) -> Option<String> {
    let mut parts: Vec<&str> = if parent.is_empty() {
        Vec::new()
    } else {
        parent.split('/').collect()
    };
    let spec = spec.replace('\\', "/");
    for part in spec.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    Some(parts.join("/"))
}

fn tree_error(message: &'static str) -> AgentError {
    AgentError::Compile(message.to_string())
}

fn assert_safe_rel(rel: &str) -> Result<()> {
    if rel.is_empty() || rel.starts_with('/') || rel.starts_with('\\') || rel.contains('\0') {
        return Err(tree_error("module tree walk failed"));
    }
    for part in rel.split(['/', '\\']) {
        if part.is_empty() || part == "." || part == ".." {
            return Err(tree_error("module tree walk failed"));
        }
    }
    Ok(())
}

fn compile_temp_root() -> Result<PathBuf> {
    select_trusted_temp_root(
        std::env::var_os("TEST_TMPDIR").as_deref().map(Path::new),
        &std::env::temp_dir(),
    )
}

fn is_trusted_existing_dir(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) => meta.is_dir() && !meta.file_type().is_symlink(),
        Err(_) => false,
    }
}

fn select_trusted_temp_root(test_tmpdir: Option<&Path>, fallback: &Path) -> Result<PathBuf> {
    if let Some(dir) = test_tmpdir
        && is_trusted_existing_dir(dir)
    {
        return Ok(dir.to_path_buf());
    }
    if is_trusted_existing_dir(fallback) {
        return Ok(fallback.to_path_buf());
    }
    Err(tree_error("module compile sandbox failed"))
}

fn create_dir_0700(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

fn create_exclusive_file(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| tree_error("module compile sandbox failed"))?;
        file.write_all(bytes)
            .map_err(|_| tree_error("module compile sandbox failed"))?;
        Ok(())
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| tree_error("module compile sandbox failed"))?;
        let meta = file
            .metadata()
            .map_err(|_| tree_error("module compile sandbox failed"))?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(tree_error("module compile sandbox failed"));
        }
        file.write_all(bytes)
            .map_err(|_| tree_error("module compile sandbox failed"))?;
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| tree_error("module compile sandbox failed"))?;
        file.write_all(bytes)
            .map_err(|_| tree_error("module compile sandbox failed"))?;
        Ok(())
    }
}

fn ensure_dir_0700(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(tree_error("module compile sandbox failed"));
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_dir_0700(path).map_err(|_| tree_error("module compile sandbox failed"))?;
            match fs::symlink_metadata(path) {
                Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => Ok(()),
                _ => Err(tree_error("module compile sandbox failed")),
            }
        }
        Err(_) => Err(tree_error("module compile sandbox failed")),
    }
}

fn ensure_parents_under_sandbox(path: &Path, sandbox: &Path) -> Result<()> {
    let relative = path
        .strip_prefix(sandbox)
        .map_err(|_| tree_error("module compile sandbox failed"))?;
    let mut current = sandbox.to_path_buf();
    let Some(parent) = relative.parent() else {
        return Ok(());
    };
    for component in parent.components() {
        match component {
            Component::Normal(_) => {
                current.push(component);
                ensure_dir_0700(&current)?;
            }
            _ => return Err(tree_error("module compile sandbox failed")),
        }
    }
    Ok(())
}

fn create_private_sandbox() -> Result<PathBuf> {
    let root = compile_temp_root()?;
    for _ in 0..64 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let name = format!(
            "{}{}-{}-{}",
            COMPILE_SANDBOX_PREFIX,
            std::process::id(),
            SANDBOX_SEQ.fetch_add(1, Ordering::Relaxed),
            nanos
        );
        let path = root.join(name);
        match create_dir_0700(&path) {
            Ok(()) => {
                if fs::symlink_metadata(&path)
                    .map(|meta| meta.is_dir() && !meta.file_type().is_symlink())
                    .unwrap_or(false)
                {
                    return Ok(path);
                }
                let _ = fs::remove_dir_all(&path);
                return Err(tree_error("module compile sandbox failed"));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(tree_error("module compile sandbox failed")),
        }
    }
    Err(tree_error("module compile sandbox failed"))
}

fn padded_allowed_root(sandbox: &Path) -> PathBuf {
    let mut allowed = sandbox.to_path_buf();
    for _ in 0..SANDBOX_PAD_DEPTH {
        allowed.push(SANDBOX_PAD_DIR);
    }
    allowed.push(SANDBOX_TREE_DIR);
    allowed
}

fn materialize_snapshot(snapshot: &ModuleSnapshot) -> Result<MaterializedSnapshot> {
    let sandbox = create_private_sandbox()?;
    let allowed_root = padded_allowed_root(&sandbox);
    let materialized = MaterializedSnapshot {
        sandbox: sandbox.clone(),
        allowed_root: allowed_root.clone(),
        entry: allowed_root.join(
            snapshot
                .entry_rel
                .replace('/', std::path::MAIN_SEPARATOR_STR),
        ),
    };
    if let Err(error) = write_snapshot_into(&materialized, snapshot) {
        drop(materialized);
        return Err(error);
    }
    Ok(materialized)
}

fn write_snapshot_into(
    materialized: &MaterializedSnapshot,
    snapshot: &ModuleSnapshot,
) -> Result<()> {
    let mut pad = materialized.sandbox.clone();
    for _ in 0..SANDBOX_PAD_DEPTH {
        pad.push(SANDBOX_PAD_DIR);
        ensure_dir_0700(&pad)?;
    }
    ensure_dir_0700(&materialized.allowed_root)?;
    for (rel, bytes) in &snapshot.files {
        assert_safe_rel(rel)?;
        let dest = materialized
            .allowed_root
            .join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        if !dest.starts_with(&materialized.allowed_root) {
            return Err(tree_error("module compile sandbox failed"));
        }
        ensure_parents_under_sandbox(&dest, &materialized.sandbox)?;
        create_exclusive_file(&dest, bytes)?;
    }
    if !materialized.entry.starts_with(&materialized.allowed_root) {
        return Err(tree_error("module compile sandbox failed"));
    }
    if !materialized.entry.is_file() {
        return Err(tree_error("module compile sandbox failed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn test_root(name: &str) -> PathBuf {
        let root = std::env::var_os("TEST_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!(
                "rss-snapshot-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("temp root");
        root
    }

    #[test]
    fn snapshot_rejects_oversize_file() {
        let root = test_root("oversize");
        let path = root.join("main.rss");
        fs::write(&path, vec![b'a'; MAX_AGENT_SOURCE_BYTES + 1]).expect("write");
        let error = module_tree_digest(&path).expect_err("oversize");
        assert_eq!(
            error.to_string(),
            format!(
                "RustScript compile error: agent source exceeds {} bytes",
                MAX_AGENT_SOURCE_BYTES
            )
        );
        assert!(!error.to_string().contains(root.to_string_lossy().as_ref()));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn snapshot_rejects_malformed_non_utf8() {
        let root = test_root("non-utf8");
        let path = root.join("main.rss");
        fs::write(&path, [0xff, 0xfe, 0xfd]).expect("write");
        let error = module_tree_digest(&path).expect_err("utf8");
        assert_eq!(
            error.to_string(),
            "RustScript compile error: module tree file is not valid UTF-8"
        );
        assert!(!error.to_string().contains(root.to_string_lossy().as_ref()));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn snapshot_rejects_outside_root_import() {
        let root = test_root("escape");
        let rss = root.join("rss");
        fs::create_dir_all(rss.join("agent")).expect("agent dir");
        fs::write(root.join("evil.rss"), "pub fn x() -> int { 1; }\n").expect("evil");
        let path = rss.join("agent").join("main.rss");
        fs::write(
            &path,
            "use super::super::evil;\npub fn run(input: map) -> string { \"ok\"; }\n",
        )
        .expect("write");
        let error = module_tree_digest(&path).expect_err("escape");
        assert_eq!(
            error.to_string(),
            "RustScript compile error: module import escapes the allowed root"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_hook_rejects_growth_after_open() {
        let root = test_root("grow");
        let path = root.join("main.rss");
        fs::write(&path, "pub fn run(input: map) -> string { \"ok\"; }\n").expect("write");
        set_after_open_hook(Some(|path| {
            let grown = "x".repeat(64);
            fs::write(path, grown).expect("grow");
        }));
        let error = module_tree_digest(&path).expect_err("grow");
        set_after_open_hook(None);
        assert_eq!(
            error.to_string(),
            "RustScript compile error: module file size changed during snapshot"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_hook_rejects_symlink_replacement_after_open() {
        static REPLACED: AtomicBool = AtomicBool::new(false);
        let root = test_root("swap");
        let path = root.join("main.rss");
        fs::write(&path, "pub fn run(input: map) -> string { \"ok\"; }\n").expect("write");
        REPLACED.store(false, Ordering::SeqCst);
        set_after_open_hook(Some(|path| {
            if REPLACED.swap(true, Ordering::SeqCst) {
                return;
            }
            let parent = path.parent().expect("parent");
            let swap = parent.join("swapped.rss");
            fs::write(&swap, "secret").expect("swap dest");
            fs::remove_file(path).expect("remove");
            std::os::unix::fs::symlink(&swap, path).expect("symlink");
        }));
        let error = module_tree_digest(&path).expect_err("swap");
        set_after_open_hook(None);
        assert_eq!(
            error.to_string(),
            "RustScript compile error: module tree contains a symlink"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn snapshot_hashes_regular_tree() {
        let root = test_root("ok");
        let path = root.join("main.rss");
        fs::write(&path, "pub fn run(input: map) -> string { \"ok\"; }\n").expect("write");
        let digest = module_tree_digest(&path).expect("digest");
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
        assert_eq!(digest, module_tree_digest(&path).expect("digest2"));
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_rejects_symlink_entry() {
        let root = test_root("symlink-entry");
        let real = root.join("real.rss");
        fs::write(&real, "pub fn run(input: map) -> string { \"ok\"; }\n").expect("write");
        let path = root.join("main.rss");
        std::os::unix::fs::symlink(&real, &path).expect("symlink");
        let error = module_tree_digest(&path).expect_err("symlink");
        assert_eq!(
            error.to_string(),
            "RustScript compile error: module tree contains a symlink"
        );
        assert!(!error.to_string().contains(root.to_string_lossy().as_ref()));
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_rejects_symlink_in_module_tree() {
        let root = test_root("symlink-tree");
        let rss = root.join("rss");
        fs::create_dir_all(rss.join("agent")).expect("dirs");
        fs::write(
            rss.join("agent").join("main.rss"),
            "use helper;\npub fn run(input: map) -> string { \"ok\"; }\n",
        )
        .expect("main");
        let helper_real = root.join("outside.rss");
        fs::write(&helper_real, "pub fn x() -> int { 1; }\n").expect("outside");
        std::os::unix::fs::symlink(&helper_real, rss.join("helper.rss")).expect("symlink");
        let error = module_tree_digest(&rss.join("agent").join("main.rss")).expect_err("symlink");
        assert_eq!(
            error.to_string(),
            "RustScript compile error: module tree contains a symlink"
        );
        assert!(!error.to_string().contains(root.to_string_lossy().as_ref()));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn snapshot_owns_bytes_after_live_files_change() {
        let root = test_root("owned-bytes");
        let path = root.join("main.rss");
        let original = "pub fn run(input: map) -> string { \"aaaa\"; }\n";
        fs::write(&path, original).expect("write");
        let snapshot = capture_module_snapshot(&path).expect("snapshot");
        assert_eq!(snapshot.entry_rel(), "main.rss");
        assert_eq!(snapshot.files().len(), 1);
        assert_eq!(snapshot.files()[0].0, "main.rss");
        assert_eq!(snapshot.files()[0].1, original.as_bytes());
        let digest = snapshot.digest().to_string();
        fs::write(&path, "pub fn run(input: map) -> string { \"bbbb\"; }\n").expect("mutate");
        assert_eq!(snapshot.files()[0].1, original.as_bytes());
        assert_eq!(snapshot.digest(), digest);
        assert_ne!(module_tree_digest(&path).expect("live"), digest);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn materialize_creates_0700_sandbox_without_symlinks_and_cleans_on_drop() {
        use std::os::unix::fs::PermissionsExt;
        let root = test_root("materialize");
        let path = root.join("main.rss");
        fs::write(&path, "pub fn run(input: map) -> string { \"ok\"; }\n").expect("write");
        let snapshot = capture_module_snapshot(&path).expect("snapshot");
        let sandbox_path;
        {
            let materialized = snapshot.materialize().expect("materialize");
            sandbox_path = materialized.sandbox().to_path_buf();
            assert!(sandbox_path.starts_with(compile_temp_root().expect("tmp")));
            let mode = fs::symlink_metadata(&sandbox_path)
                .expect("meta")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
            assert!(materialized.allowed_root().starts_with(&sandbox_path));
            assert!(
                materialized
                    .entry()
                    .starts_with(materialized.allowed_root())
            );
            assert_ne!(materialized.entry(), path.as_path());
            assert_eq!(
                fs::read(materialized.entry()).expect("read copy"),
                snapshot.files()[0].1
            );
            assert!(
                !fs::symlink_metadata(materialized.entry())
                    .expect("entry meta")
                    .file_type()
                    .is_symlink()
            );
            fs::write(&path, "mutated").expect("mutate original");
            assert_eq!(
                fs::read(materialized.entry()).expect("copy unchanged"),
                snapshot.files()[0].1
            );
        }
        assert!(!sandbox_path.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn materialize_cleans_sandbox_on_panic() {
        let root = test_root("materialize-panic");
        let path = root.join("main.rss");
        fs::write(&path, "pub fn run(input: map) -> string { \"ok\"; }\n").expect("write");
        let snapshot = capture_module_snapshot(&path).expect("snapshot");
        let sandbox_path = std::sync::Mutex::new(None);
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let materialized = snapshot.materialize().expect("materialize");
            *sandbox_path.lock().expect("lock") = Some(materialized.sandbox().to_path_buf());
            panic!("forced compile panic");
        }));
        assert!(panicked.is_err());
        let sandbox_path = sandbox_path.lock().expect("lock").clone().expect("path");
        assert!(!sandbox_path.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn snapshot_rejects_absolute_import() {
        let root = test_root("absolute-import");
        let path = root.join("main.rss");
        fs::write(
            &path,
            "use /tmp/evil.rss;\npub fn run(input: map) -> string { \"ok\"; }\n",
        )
        .expect("write");
        let error = match capture_module_snapshot(&path) {
            Ok(_) => panic!("absolute import must fail"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            message.contains("malformed")
                || message.contains("unsupported")
                || message.contains("escapes")
                || message.contains("expected"),
            "absolute import must fail closed, got {message}"
        );
        assert!(!message.contains(root.to_string_lossy().as_ref()));
        assert!(!message.contains("/tmp/evil.rss"), "{message}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn snapshot_ignores_fake_use_in_comments_and_strings() {
        let root = test_root("fake-use");
        let path = root.join("main.rss");
        fs::write(
            &path,
            "// use super::evil;\n/* use super::evil; */\npub fn run(input: map) -> string {\n    let s: string = \"use super::evil;\";\n    \"ok\";\n}\n",
        )
        .expect("write");
        capture_module_snapshot(&path).expect("comments and strings must not look like imports");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn snapshot_discovers_use_with_whitespace_and_comments_between_tokens() {
        let root = test_root("spaced-use");
        let rss = root.join("rss");
        fs::create_dir_all(rss.join("agent")).expect("agent dir");
        fs::write(root.join("evil.rss"), "pub fn x() -> int { 1; }\n").expect("evil");
        let path = rss.join("agent").join("main.rss");
        fs::write(
            &path,
            "use\n\t/* comments between tokens */\n\t\u{2003}super::super::evil;\npub fn run(input: map) -> string { \"ok\"; }\n",
        )
        .expect("write");
        let error = capture_module_snapshot(&path).expect_err("escape");
        assert_eq!(
            error.to_string(),
            "RustScript compile error: module import escapes the allowed root"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn snapshot_rejects_crate_import_explicitly() {
        let root = test_root("crate-import");
        let path = root.join("main.rss");
        fs::write(
            &path,
            "use crate::evil;\npub fn run(input: map) -> string { \"ok\"; }\n",
        )
        .expect("write");
        let error = capture_module_snapshot(&path).expect_err("crate");
        let message = error.to_string();
        assert!(
            message.contains("crate"),
            "crate import must be rejected explicitly, got {message}"
        );
        assert!(!message.contains("escapes the allowed root"), "{message}");
        assert!(!message.contains(root.to_string_lossy().as_ref()));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn snapshot_rejects_pub_use_as_unsupported() {
        let root = test_root("pub-use");
        let path = root.join("main.rss");
        fs::write(
            &path,
            "pub use helper;\npub fn run(input: map) -> string { \"ok\"; }\n",
        )
        .expect("write");
        let error = capture_module_snapshot(&path).expect_err("pub use");
        let message = error.to_string();
        assert!(
            message.contains("malformed")
                || message.contains("unsupported")
                || message.contains("expected"),
            "pub use must fail closed, got {message}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn snapshot_accepts_grouped_imports_aliases_and_self() {
        let root = test_root("grouped");
        let rss = root.join("rss");
        fs::create_dir_all(rss.join("agent")).expect("agent dir");
        fs::write(
            rss.join("agent").join("helper.rss"),
            "pub fn value() -> int { 1; }\n",
        )
        .expect("helper");
        let path = rss.join("agent").join("main.rss");
        fs::write(
            &path,
            "use self::helper::{value as answer};\nuse helper as h;\npub fn run(input: map) -> string { \"ok\"; }\n",
        )
        .expect("write");
        capture_module_snapshot(&path).expect("grouped and alias imports stay in root");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn snapshot_rejects_unterminated_comment_and_string() {
        let root = test_root("unterminated");
        let comment = root.join("comment.rss");
        fs::write(
            &comment,
            "/* unterminated\npub fn run(input: map) -> string { \"ok\"; }\n",
        )
        .expect("write");
        let error = capture_module_snapshot(&comment).expect_err("comment");
        assert!(
            error.to_string().contains("malformed") || error.to_string().contains("unterminated"),
            "{}",
            error
        );
        let string_path = root.join("string.rss");
        fs::write(
            &string_path,
            "pub fn run(input: map) -> string { \"unterminated\n",
        )
        .expect("write");
        let error = capture_module_snapshot(&string_path).expect_err("string");
        assert!(
            error.to_string().contains("malformed") || error.to_string().contains("unterminated"),
            "{}",
            error
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn snapshot_non_nesting_block_comment_matches_parser() {
        let root = test_root("nested-comment");
        let rss = root.join("rss");
        fs::create_dir_all(rss.join("agent")).expect("agent dir");
        fs::write(root.join("evil.rss"), "pub fn x() -> int { 1; }\n").expect("evil");
        let path = rss.join("agent").join("main.rss");
        fs::write(
            &path,
            "/* outer /* inner */ use super::super::evil;\npub fn run(input: map) -> string { \"ok\"; }\n",
        )
        .expect("write");
        let error = capture_module_snapshot(&path).expect_err("inner close ends comment");
        assert_eq!(
            error.to_string(),
            "RustScript compile error: module import escapes the allowed root"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn snapshot_rejects_one_over_tree_node_bound_for_junk_files() {
        let root = test_root("junk-nodes");
        let path = root.join("main.rss");
        fs::write(&path, "pub fn run(input: map) -> string { \"ok\"; }\n").expect("main");
        for i in 0..MAX_TREE_NODES {
            fs::write(root.join(format!("junk-{i}.txt")), "x").expect("junk");
        }
        let error = capture_module_snapshot(&path).expect_err("nodes");
        assert_eq!(
            error.to_string(),
            "RustScript compile error: module tree exceeds the entry count bound"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn select_compile_temp_root_skips_symlink_tmpdir() {
        let root = test_root("symlink-tmpdir");
        let real = root.join("real");
        fs::create_dir(&real).expect("real");
        let link = root.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let fallback = root.join("fallback");
        fs::create_dir(&fallback).expect("fallback");
        let chosen = select_trusted_temp_root(Some(link.as_path()), &fallback).expect("choose");
        assert_eq!(chosen, fallback);
        assert!(
            select_trusted_temp_root(Some(link.as_path()), &link).is_err(),
            "symlink-only roots must fail closed"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
