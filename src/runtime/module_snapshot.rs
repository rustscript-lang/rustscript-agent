//! Immutable module-tree snapshot for RSS `from_file` compilation.
//!
//! The snapshot owns every regular `.rss` file under the allowed module root
//! (the nearest ancestor directory named `rss`, or the entry file's parent)
//! plus the entry's relative path and digest. Relpaths and file bytes are
//! length-prefixed into SHA-256. Compilation materializes this owned snapshot
//! into an isolated sandbox; the compiler never re-reads the original live
//! files.

use std::collections::BTreeSet;
#[cfg(test)]
use std::fs;
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "linux")]
use std::ffi::{CStr, CString, OsStr, OsString};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;

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
const ERR_SECURE_OPERATION_UNSUPPORTED: &str = "secure module tree operation unsupported";
const ERR_MODULE_TREE_SYMLINK: &str = "module tree contains a symlink";
const ERR_MODULE_TREE_WALK: &str = "module tree walk failed";
const ERR_SANDBOX: &str = "module compile sandbox failed";
const ERR_AMBIGUOUS_PATH: &str = "module tree contains an ambiguous path component";
const ERR_AMBIGUOUS_IDENTITY: &str = "module tree contains ambiguous module identities";
#[cfg(target_os = "linux")]
static SANDBOX_SEQ: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static SANDBOX_CLEANUP_FAILURES: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "linux")]
struct SandboxCleanup {
    temp_root: File,
    sandbox_dir: File,
    sandbox_name: OsString,
}

#[cfg(target_os = "linux")]
struct PrivateSandbox {
    path: PathBuf,
    name: OsString,
    temp_root: File,
    dir: File,
}

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
/// through the trusted temporary-root handle in `Drop`.
pub struct MaterializedSnapshot {
    sandbox: PathBuf,
    allowed_root: PathBuf,
    entry: PathBuf,
    #[cfg(target_os = "linux")]
    allowed_root_dir: File,
    #[cfg(target_os = "linux")]
    cleanup: SandboxCleanup,
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
        vec![dest.to_string_lossy().replace('\\', "/")]
    }
}

impl Drop for MaterializedSnapshot {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if cleanup_sandbox(&self.cleanup).is_err() {
            SANDBOX_CLEANUP_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
thread_local! {
    static AFTER_OPEN_HOOK: Cell<Option<fn(&Path)>> = const { Cell::new(None) };
    static AFTER_DIRECTORY_OPEN_HOOK: Cell<Option<fn(&Path)>> = const { Cell::new(None) };
    static AFTER_SANDBOX_DIR_HOOK: Cell<Option<fn(&Path)>> = const { Cell::new(None) };
}

/// Test-only hook invoked after a regular file is opened and before its bytes
/// are read, so TOCTOU grow/replacement cases can be driven deterministically.
#[cfg(test)]
pub fn set_after_open_hook(hook: Option<fn(&Path)>) {
    AFTER_OPEN_HOOK.with(|cell| cell.set(hook));
}

/// Test-only hook invoked after a directory is opened and before its children
/// are enumerated, so an ancestor replacement race can be driven
/// deterministically.
#[cfg(test)]
pub fn set_after_directory_open_hook(hook: Option<fn(&Path)>) {
    AFTER_DIRECTORY_OPEN_HOOK.with(|cell| cell.set(hook));
}

/// Test-only hook invoked after the sandbox tree directory is prepared and
/// before snapshot files are written.
#[cfg(test)]
pub fn set_after_sandbox_dir_hook(hook: Option<fn(&Path)>) {
    AFTER_SANDBOX_DIR_HOOK.with(|cell| cell.set(hook));
}

pub fn module_tree_digest(entry: &Path) -> Result<String> {
    Ok(capture_module_snapshot(entry)?.digest)
}

pub fn capture_module_snapshot(entry: &Path) -> Result<ModuleSnapshot> {
    let root = module_tree_root(entry)?;
    let entry_rel = relative_posix(&root, entry)?;
    assert_safe_rel(&entry_rel)?;
    let mut files = Vec::new();
    let mut total_bytes = 0usize;
    let mut nodes = 1usize;
    let root_dir = open_module_root(&root)?;
    walk_dir(
        &root,
        &root_dir,
        &root,
        0,
        &mut files,
        &mut total_bytes,
        &mut nodes,
    )?;
    files.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    assert_unique_rel_identities(&files)?;
    if !files.iter().any(|(rel, _)| rel == &entry_rel) {
        return Err(tree_error(ERR_MODULE_TREE_WALK));
    }
    assert_imports_stay_in_root(&root, &files)?;
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

#[cfg(target_os = "linux")]
fn walk_dir(
    root: &Path,
    dir: &File,
    path: &Path,
    depth: usize,
    files: &mut Vec<(String, Vec<u8>)>,
    total_bytes: &mut usize,
    nodes: &mut usize,
) -> Result<()> {
    if depth > MAX_TREE_DEPTH {
        return Err(tree_error("module tree exceeds the depth bound"));
    }
    invoke_after_directory_open(path);
    let mut children = read_dir_names(dir)?;
    children.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    for name in children {
        *nodes = nodes
            .checked_add(1)
            .ok_or_else(|| tree_error("module tree exceeds the entry count bound"))?;
        if *nodes > MAX_TREE_NODES {
            return Err(tree_error("module tree exceeds the entry count bound"));
        }
        let child_path = path.join(&name);
        let child = open_readonly_at(dir, &name).map_err(map_source_open_error)?;
        let metadata = child
            .metadata()
            .map_err(|_| tree_error(ERR_MODULE_TREE_WALK))?;
        if metadata.is_dir() {
            walk_dir(
                root,
                &child,
                &child_path,
                depth.saturating_add(1),
                files,
                total_bytes,
                nodes,
            )?;
            continue;
        }
        if !metadata.is_file() {
            return Err(tree_error(ERR_MODULE_TREE_WALK));
        }
        if child_path.extension().and_then(|ext| ext.to_str()) != Some("rss") {
            continue;
        }
        if files.len() >= MAX_TREE_FILES {
            return Err(tree_error("module tree exceeds the file count bound"));
        }
        let bytes = read_regular_file_capped(&child, dir, &name, &child_path)?;
        let next_total = total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| tree_error("module tree exceeds the byte bound"))?;
        if next_total > MAX_TREE_BYTES {
            return Err(tree_error("module tree exceeds the byte bound"));
        }
        *total_bytes = next_total;
        files.push((relative_posix(root, &child_path)?, bytes));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn walk_dir(
    _root: &Path,
    _dir: &File,
    _path: &Path,
    _depth: usize,
    _files: &mut Vec<(String, Vec<u8>)>,
    _total_bytes: &mut usize,
    _nodes: &mut usize,
) -> Result<()> {
    Err(tree_error(ERR_SECURE_OPERATION_UNSUPPORTED))
}

#[cfg(target_os = "linux")]
fn read_regular_file_capped(
    file: &File,
    parent: &File,
    name: &OsStr,
    path: &Path,
) -> Result<Vec<u8>> {
    let meta = file
        .metadata()
        .map_err(|_| tree_error(ERR_MODULE_TREE_WALK))?;
    if !meta.is_file() {
        return Err(tree_error(ERR_MODULE_TREE_WALK));
    }
    let limit = meta.len();
    if limit > MAX_AGENT_SOURCE_BYTES as u64 {
        return Err(AgentError::Compile(format!(
            "agent source exceeds {} bytes",
            MAX_AGENT_SOURCE_BYTES
        )));
    }
    invoke_after_open(path);
    let mut reader = Read::take(file, limit.saturating_add(1));
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| tree_error(ERR_MODULE_TREE_WALK))?;
    if bytes.len() as u64 != limit {
        return Err(tree_error("module file size changed during snapshot"));
    }
    let after = file
        .metadata()
        .map_err(|_| tree_error(ERR_MODULE_TREE_WALK))?;
    if after.len() != limit
        || !after.is_file()
        || after.ino() != meta.ino()
        || after.dev() != meta.dev()
    {
        return Err(tree_error("module file size changed during snapshot"));
    }
    let current = open_readonly_at(parent, name).map_err(map_source_open_error)?;
    let current_meta = current
        .metadata()
        .map_err(|_| tree_error(ERR_MODULE_TREE_WALK))?;
    if !current_meta.is_file()
        || current_meta.ino() != meta.ino()
        || current_meta.dev() != meta.dev()
        || current_meta.len() != limit
    {
        return Err(tree_error("module file size changed during snapshot"));
    }
    if std::str::from_utf8(&bytes).is_err() {
        return Err(tree_error("module tree file is not valid UTF-8"));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn open_module_root(path: &Path) -> Result<File> {
    let absolute = absolute_path(path)?;
    open_directory_absolute(&absolute).map_err(map_source_open_error)
}

#[cfg(not(target_os = "linux"))]
fn open_module_root(_path: &Path) -> Result<File> {
    Err(tree_error(ERR_SECURE_OPERATION_UNSUPPORTED))
}

#[cfg(target_os = "linux")]
fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::env::current_dir()
        .map(|current| current.join(path))
        .map_err(|_| tree_error(ERR_MODULE_TREE_WALK))
}

#[cfg(target_os = "linux")]
fn open_directory_absolute(path: &Path) -> io::Result<File> {
    let mut current = open_root_directory()?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                current = open_directory_at(&current, name)?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "parent path"));
            }
        }
    }
    Ok(current)
}

#[cfg(target_os = "linux")]
fn open_root_directory() -> io::Result<File> {
    let path = b"/\0";
    // SAFETY: the byte string is NUL terminated and the returned descriptor is
    // owned by the File created below.
    let fd = unsafe {
        libc::open(
            path.as_ptr().cast(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a newly acquired descriptor and is transferred exactly
    // once to File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn open_directory_at(parent: &File, name: &OsStr) -> io::Result<File> {
    let directory = open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() {
        return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn open_readonly_at(parent: &File, name: &OsStr) -> io::Result<File> {
    open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
}

#[cfg(target_os = "linux")]
fn open_write_exclusive_at(parent: &File, name: &OsStr) -> io::Result<File> {
    open_at(
        parent,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )
}

#[cfg(target_os = "linux")]
fn open_at(parent: &File, name: &OsStr, flags: i32, mode: libc::mode_t) -> io::Result<File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path component"))?;
    // SAFETY: name is NUL terminated, parent owns a live directory fd, and
    // the descriptor is transferred to File only on success.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a newly acquired descriptor and is transferred exactly
    // once to File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn create_directory_at(parent: &File, name: &OsStr) -> io::Result<()> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path component"))?;
    // SAFETY: name is NUL terminated and parent owns a live directory fd.
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_dir_names(dir: &File) -> Result<Vec<OsString>> {
    let independent = open_at(
        dir,
        OsStr::new("."),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )
    .map_err(|_| tree_error(ERR_MODULE_TREE_WALK))?;
    // SAFETY: dup creates a descriptor owned by the directory stream, leaving
    // both the File's descriptor and the independent open description intact.
    let duplicate = unsafe { libc::dup(independent.as_raw_fd()) };
    if duplicate < 0 {
        return Err(tree_error(ERR_MODULE_TREE_WALK));
    }
    // SAFETY: fdopendir takes ownership of duplicate on success.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: fdopendir did not take ownership on failure.
        unsafe { libc::close(duplicate) };
        return Err(tree_error(ERR_MODULE_TREE_WALK));
    }
    let mut names = Vec::new();
    let mut read_error = None;
    loop {
        // SAFETY: stream is a valid directory stream and errno is thread-local.
        let entry = unsafe {
            *libc::__errno_location() = 0;
            libc::readdir(stream)
        };
        if entry.is_null() {
            // SAFETY: errno is thread-local and the stream remains valid.
            let errno = unsafe { *libc::__errno_location() };
            if errno != 0 {
                read_error = Some(io::Error::from_raw_os_error(errno));
            }
            break;
        }
        // SAFETY: d_name is NUL terminated by readdir for a valid dirent.
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes != b"." && bytes != b".." {
            names.push(OsString::from_vec(bytes.to_vec()));
        }
    }
    // SAFETY: stream is closed exactly once here.
    let close_error = unsafe { libc::closedir(stream) };
    if read_error.is_some() || close_error != 0 {
        return Err(tree_error(ERR_MODULE_TREE_WALK));
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
fn map_source_open_error(error: io::Error) -> AgentError {
    if error.raw_os_error() == Some(libc::ELOOP) {
        return tree_error(ERR_MODULE_TREE_SYMLINK);
    }
    if error.raw_os_error() == Some(libc::ENOSYS) {
        return tree_error(ERR_SECURE_OPERATION_UNSUPPORTED);
    }
    tree_error(ERR_MODULE_TREE_WALK)
}

#[cfg(test)]
fn invoke_after_open(path: &Path) {
    AFTER_OPEN_HOOK.with(|cell| {
        if let Some(hook) = cell.get() {
            hook(path);
        }
    });
}

#[cfg(test)]
fn invoke_after_directory_open(path: &Path) {
    AFTER_DIRECTORY_OPEN_HOOK.with(|cell| {
        if let Some(hook) = cell.get() {
            hook(path);
        }
    });
}

#[cfg(test)]
fn invoke_after_sandbox_dir(path: &Path) {
    AFTER_SANDBOX_DIR_HOOK.with(|cell| {
        if let Some(hook) = cell.get() {
            hook(path);
        }
    });
}

#[cfg(not(test))]
fn invoke_after_open(_path: &Path) {}

#[cfg(not(test))]
fn invoke_after_directory_open(_path: &Path) {}

#[cfg(not(test))]
fn invoke_after_sandbox_dir(_path: &Path) {}

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
    if spec.contains('\\') {
        return Err(tree_error(ERR_AMBIGUOUS_PATH));
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

fn assert_unique_rel_identities(files: &[(String, Vec<u8>)]) -> Result<()> {
    let mut normalized = BTreeSet::new();
    for (rel, _) in files {
        assert_safe_rel(rel)?;
        // This key is for collision detection only. It is never registered as
        // a compiler override, so no lossy alias can affect module loading.
        let key = rel.replace('\\', "/");
        if !normalized.insert(key) {
            return Err(tree_error(ERR_AMBIGUOUS_IDENTITY));
        }
    }
    Ok(())
}

fn assert_safe_rel(rel: &str) -> Result<()> {
    if rel.is_empty() || rel.starts_with('/') || rel.contains('\0') {
        return Err(tree_error(ERR_MODULE_TREE_WALK));
    }
    #[cfg(unix)]
    if rel.contains('\\') {
        return Err(tree_error(ERR_AMBIGUOUS_PATH));
    }
    for part in rel.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(tree_error(ERR_MODULE_TREE_WALK));
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

#[cfg(target_os = "linux")]
fn is_trusted_existing_dir(path: &Path) -> bool {
    let Ok(absolute) = absolute_path(path) else {
        return false;
    };
    open_directory_absolute(&absolute).is_ok()
}

#[cfg(not(target_os = "linux"))]
fn is_trusted_existing_dir(_path: &Path) -> bool {
    false
}

fn select_trusted_temp_root(test_tmpdir: Option<&Path>, fallback: &Path) -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        if let Some(dir) = test_tmpdir
            && is_trusted_existing_dir(dir)
        {
            return absolute_path(dir);
        }
        if is_trusted_existing_dir(fallback) {
            return absolute_path(fallback);
        }
        Err(tree_error(ERR_SANDBOX))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (test_tmpdir, fallback);
        Err(tree_error(ERR_SECURE_OPERATION_UNSUPPORTED))
    }
}

#[cfg(target_os = "linux")]
fn map_sandbox_open_error(error: io::Error) -> AgentError {
    if error.raw_os_error() == Some(libc::ENOSYS) {
        return tree_error(ERR_SECURE_OPERATION_UNSUPPORTED);
    }
    tree_error(ERR_SANDBOX)
}

#[cfg(target_os = "linux")]
fn ensure_directory_at(parent: &File, name: &OsStr) -> Result<File> {
    match create_directory_at(parent, name) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(tree_error(ERR_SANDBOX)),
    }
    let directory = open_directory_at(parent, name).map_err(map_sandbox_open_error)?;
    let metadata = directory.metadata().map_err(|_| tree_error(ERR_SANDBOX))?;
    if !metadata.is_dir() {
        return Err(tree_error(ERR_SANDBOX));
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn open_relative_directory(root: &File, relative: &str) -> Result<File> {
    let mut current = root.try_clone().map_err(|_| tree_error(ERR_SANDBOX))?;
    if relative.is_empty() {
        return Ok(current);
    }
    for component in relative.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(tree_error(ERR_SANDBOX));
        }
        current =
            open_directory_at(&current, OsStr::new(component)).map_err(map_sandbox_open_error)?;
    }
    Ok(current)
}

#[cfg(target_os = "linux")]
fn ensure_parents_at(root: &File, relative_file: &str) -> Result<File> {
    let parent = relative_file
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or("");
    let mut current = root.try_clone().map_err(|_| tree_error(ERR_SANDBOX))?;
    if parent.is_empty() {
        return Ok(current);
    }
    for component in parent.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(tree_error(ERR_SANDBOX));
        }
        current = ensure_directory_at(&current, OsStr::new(component))?;
    }
    Ok(current)
}

#[cfg(target_os = "linux")]
fn verify_parent_directory(root: &File, relative_file: &str, expected: &File) -> Result<()> {
    let parent = relative_file
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or("");
    let current = open_relative_directory(root, parent)?;
    let expected_meta = expected.metadata().map_err(|_| tree_error(ERR_SANDBOX))?;
    let current_meta = current.metadata().map_err(|_| tree_error(ERR_SANDBOX))?;
    if !current_meta.is_dir()
        || current_meta.dev() != expected_meta.dev()
        || current_meta.ino() != expected_meta.ino()
    {
        return Err(tree_error(ERR_SANDBOX));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_relative_file(root: &File, relative_file: &str) -> Result<File> {
    let (parent, name) = relative_file
        .rsplit_once('/')
        .unwrap_or(("", relative_file));
    let directory = open_relative_directory(root, parent)?;
    open_readonly_at(&directory, OsStr::new(name)).map_err(map_sandbox_open_error)
}

#[cfg(target_os = "linux")]
fn create_private_sandbox() -> Result<PrivateSandbox> {
    let root = compile_temp_root()?;
    let temp_root = open_directory_absolute(&root).map_err(map_sandbox_open_error)?;
    for _ in 0..64 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let name = OsString::from(format!(
            "{}{}-{}-{}",
            COMPILE_SANDBOX_PREFIX,
            std::process::id(),
            SANDBOX_SEQ.fetch_add(1, Ordering::Relaxed),
            nanos
        ));
        match create_directory_at(&temp_root, &name) {
            Ok(()) => {
                let dir = match open_directory_at(&temp_root, &name) {
                    Ok(dir) => dir,
                    Err(error) => {
                        let _ = unlink_at(&temp_root, &name, libc::AT_REMOVEDIR);
                        return Err(map_sandbox_open_error(error));
                    }
                };
                return Ok(PrivateSandbox {
                    path: root.join(&name),
                    name,
                    temp_root,
                    dir,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(tree_error(ERR_SANDBOX)),
        }
    }
    Err(tree_error(ERR_SANDBOX))
}

#[cfg(not(target_os = "linux"))]
fn create_private_sandbox() -> Result<()> {
    Err(tree_error(ERR_SECURE_OPERATION_UNSUPPORTED))
}

fn padded_allowed_root(sandbox: &Path) -> PathBuf {
    let mut allowed = sandbox.to_path_buf();
    for _ in 0..SANDBOX_PAD_DEPTH {
        allowed.push(SANDBOX_PAD_DIR);
    }
    allowed.push(SANDBOX_TREE_DIR);
    allowed
}

#[cfg(target_os = "linux")]
fn setup_sandbox_dirs(sandbox: &File) -> Result<File> {
    let mut current = sandbox.try_clone().map_err(|_| tree_error(ERR_SANDBOX))?;
    for _ in 0..SANDBOX_PAD_DEPTH {
        current = ensure_directory_at(&current, OsStr::new(SANDBOX_PAD_DIR))?;
    }
    ensure_directory_at(&current, OsStr::new(SANDBOX_TREE_DIR))
}

#[cfg(target_os = "linux")]
fn cleanup_with_counter(cleanup: &SandboxCleanup) {
    if cleanup_sandbox(cleanup).is_err() {
        SANDBOX_CLEANUP_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(target_os = "linux")]
fn materialize_snapshot(snapshot: &ModuleSnapshot) -> Result<MaterializedSnapshot> {
    let private = create_private_sandbox()?;
    let cleanup = SandboxCleanup {
        temp_root: private.temp_root,
        sandbox_dir: private.dir,
        sandbox_name: private.name,
    };
    let sandbox_dir = match cleanup.sandbox_dir.try_clone() {
        Ok(dir) => dir,
        Err(_) => {
            cleanup_with_counter(&cleanup);
            return Err(tree_error(ERR_SANDBOX));
        }
    };
    let allowed_root_dir = match setup_sandbox_dirs(&sandbox_dir) {
        Ok(dir) => dir,
        Err(error) => {
            cleanup_with_counter(&cleanup);
            return Err(error);
        }
    };
    let sandbox = private.path;
    let allowed_root = padded_allowed_root(&sandbox);
    let entry = allowed_root.join(
        snapshot
            .entry_rel
            .replace('/', std::path::MAIN_SEPARATOR_STR),
    );
    let materialized = MaterializedSnapshot {
        sandbox,
        allowed_root,
        entry,
        allowed_root_dir,
        cleanup,
    };
    if let Err(error) = write_snapshot_into(&materialized, snapshot) {
        drop(materialized);
        return Err(error);
    }
    Ok(materialized)
}

#[cfg(not(target_os = "linux"))]
fn materialize_snapshot(_snapshot: &ModuleSnapshot) -> Result<MaterializedSnapshot> {
    Err(tree_error(ERR_SECURE_OPERATION_UNSUPPORTED))
}

#[cfg(target_os = "linux")]
fn write_snapshot_into(
    materialized: &MaterializedSnapshot,
    snapshot: &ModuleSnapshot,
) -> Result<()> {
    for (rel, bytes) in &snapshot.files {
        assert_safe_rel(rel)?;
        let parent = ensure_parents_at(&materialized.allowed_root_dir, rel)?;
        invoke_after_sandbox_dir(&materialized.allowed_root);
        verify_parent_directory(&materialized.allowed_root_dir, rel, &parent)?;
        let name = rel.rsplit_once('/').map(|(_, name)| name).unwrap_or(rel);
        let mut file = open_write_exclusive_at(&parent, OsStr::new(name))
            .map_err(|_| tree_error(ERR_SANDBOX))?;
        file.write_all(bytes).map_err(|_| tree_error(ERR_SANDBOX))?;
        let metadata = file.metadata().map_err(|_| tree_error(ERR_SANDBOX))?;
        if !metadata.is_file() || metadata.len() != bytes.len() as u64 {
            return Err(tree_error(ERR_SANDBOX));
        }
        verify_parent_directory(&materialized.allowed_root_dir, rel, &parent)?;
    }
    let entry = open_relative_file(&materialized.allowed_root_dir, &snapshot.entry_rel)?;
    let metadata = entry.metadata().map_err(|_| tree_error(ERR_SANDBOX))?;
    if !metadata.is_file() {
        return Err(tree_error(ERR_SANDBOX));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn unlink_at(parent: &File, name: &OsStr, flags: i32) -> io::Result<()> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path component"))?;
    // SAFETY: name is NUL terminated and parent owns a live directory fd.
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_directory_contents(dir: &File) -> io::Result<()> {
    let names = read_dir_names(dir)
        .map_err(|_| io::Error::other("sandbox directory enumeration failed"))?;
    for name in names {
        match open_directory_at(dir, &name) {
            Ok(child) => {
                cleanup_directory_contents(&child)?;
                match unlink_at(dir, &name, libc::AT_REMOVEDIR) {
                    Ok(()) => {}
                    Err(error)
                        if matches!(
                            error.raw_os_error(),
                            Some(libc::ELOOP) | Some(libc::ENOTDIR)
                        ) =>
                    {
                        unlink_at(dir, &name, 0)?
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) => {
                unlink_at(dir, &name, 0)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_sandbox(cleanup: &SandboxCleanup) -> io::Result<()> {
    cleanup_directory_contents(&cleanup.sandbox_dir)?;
    unlink_at(
        &cleanup.temp_root,
        &cleanup.sandbox_name,
        libc::AT_REMOVEDIR,
    )
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

    #[cfg(unix)]
    #[test]
    fn snapshot_rejects_literal_backslash_path_identity_collision() {
        let root = test_root("backslash-collision");
        let rss = root.join("rss");
        fs::create_dir_all(rss.join("a")).expect("a dir");
        let slash_path = rss.join("a").join("b.rss");
        let backslash_path = rss.join("a\\b.rss");
        fs::write(
            &slash_path,
            "pub fn run(input: map) -> string { \"SLASH\"; }\n",
        )
        .expect("slash module");
        fs::write(
            &backslash_path,
            "pub fn value() -> string { \"BACKSLASH\"; }\n",
        )
        .expect("literal backslash module");

        let error = capture_module_snapshot(&slash_path)
            .expect_err("native path identities that normalize to one import key must fail");
        assert!(
            error.to_string().contains("ambiguous"),
            "ambiguous native identity must fail with a bounded diagnostic: {error}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_directory_handle_survives_ancestor_replacement() {
        static SWAPPED: AtomicBool = AtomicBool::new(false);
        let root = test_root("ancestor-replacement");
        let input = root.join("input");
        let outside = root.join("outside");
        let inside_agent = input.join("link").join("agent");
        let outside_agent = outside.join("agent");
        fs::create_dir_all(&inside_agent).expect("inside agent");
        fs::create_dir_all(&outside_agent).expect("outside agent");
        let entry = inside_agent.join("main.rss");
        fs::write(&entry, "pub fn run(input: map) -> string { \"INSIDE\"; }\n")
            .expect("inside source");
        fs::write(
            outside_agent.join("main.rss"),
            "pub fn run(input: map) -> string { \"OUTSIDE\"; }\n",
        )
        .expect("outside source");
        SWAPPED.store(false, Ordering::SeqCst);
        set_after_directory_open_hook(Some(|path| {
            if SWAPPED.swap(true, Ordering::SeqCst) {
                return;
            }
            let link = path.parent().expect("link");
            let input = link.parent().expect("input");
            let root = input.parent().expect("root");
            fs::rename(link, root.join("link-original")).expect("rename original link");
            std::os::unix::fs::symlink(root.join("outside"), link).expect("replace link");
        }));
        let snapshot = capture_module_snapshot(&entry);
        set_after_directory_open_hook(None);
        let snapshot = snapshot.expect("opened directory handle must remain inside");
        assert_eq!(
            snapshot.files()[0].1,
            b"pub fn run(input: map) -> string { \"INSIDE\"; }\n"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn materialize_rejects_sandbox_ancestor_replacement_without_outside_write() {
        static SWAPPED: AtomicBool = AtomicBool::new(false);
        static OUTSIDE: OnceLock<std::sync::Mutex<Option<PathBuf>>> = OnceLock::new();
        let root = test_root("sandbox-replacement");
        let path = root.join("rss").join("agent").join("main.rss");
        fs::create_dir_all(path.parent().expect("source parent")).expect("source parent");
        fs::write(&path, "pub fn run(input: map) -> string { \"ok\"; }\n").expect("source");
        let snapshot = capture_module_snapshot(&path).expect("snapshot");
        SWAPPED.store(false, Ordering::SeqCst);
        *OUTSIDE
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .expect("outside lock") = None;
        set_after_sandbox_dir_hook(Some(|allowed_root| {
            if SWAPPED.swap(true, Ordering::SeqCst) {
                return;
            }
            let parent = allowed_root.join("agent");
            let parent_dir = parent.parent().expect("allowed parent");
            let original = parent_dir.join("agent-original");
            let outside = parent_dir.join("agent-outside");
            fs::rename(&parent, &original).expect("rename parent");
            fs::create_dir(&outside).expect("outside tree");
            std::os::unix::fs::symlink(&outside, &parent).expect("replace parent");
            *OUTSIDE
                .get_or_init(|| std::sync::Mutex::new(None))
                .lock()
                .expect("outside lock") = Some(outside);
        }));
        let result = snapshot.materialize();
        set_after_sandbox_dir_hook(None);
        let (succeeded, error) = match result {
            Ok(materialized) => {
                drop(materialized);
                (true, None)
            }
            Err(error) => (false, Some(error.to_string())),
        };
        let outside = OUTSIDE
            .get()
            .and_then(|slot| slot.lock().expect("outside lock").clone())
            .expect("race target");
        let allowed_root = outside.parent().expect("allowed root").to_path_buf();
        let replaced_parent = allowed_root.join("agent");
        let original_parent = allowed_root.join("agent-original");
        let mut sandbox = allowed_root.clone();
        for _ in 0..(SANDBOX_PAD_DEPTH + 1) {
            sandbox.pop();
        }
        assert!(!succeeded, "sandbox path replacement must fail closed");
        assert_eq!(
            error.as_deref(),
            Some("RustScript compile error: module compile sandbox failed")
        );
        assert!(
            !outside.join("main.rss").exists(),
            "sandbox replacement must never write outside the allowed tree"
        );
        let _ = fs::remove_file(&replaced_parent);
        let _ = fs::remove_dir_all(&outside);
        let _ = fs::remove_dir_all(&original_parent);
        let _ = fs::remove_dir_all(&sandbox);
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
