//! Immutable module-tree snapshot for RSS `from_file` compilation.
//!
//! The snapshot owns every regular `.rss` file under the allowed module root
//! (the nearest ancestor directory named `rss`, or the entry file's parent)
//! plus the entry's relative path and digest. Relpaths and file bytes are
//! length-prefixed into SHA-256. Compilation materializes this owned snapshot
//! into an isolated sandbox; the compiler never re-reads the original live
//! files.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
use std::cell::Cell;

use crate::capabilities::sha256_hex;

use super::rss_runner::{AgentError, MAX_AGENT_SOURCE_BYTES, Result};

const MAX_TREE_FILES: usize = 256;
const MAX_TREE_DEPTH: usize = 16;
const MAX_TREE_BYTES: usize = 8 * 1024 * 1024;
const COMPILE_SANDBOX_PREFIX: &str = "rss-compile-sandbox-";
const SANDBOX_TREE_DIR: &str = "tree";
static SANDBOX_SEQ: AtomicU64 = AtomicU64::new(0);

/// Owned module-tree bytes used for digesting and isolated compilation.
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
    pub fn entry_rel(&self) -> &str {
        &self.entry_rel
    }

    #[cfg(test)]
    pub fn files(&self) -> &[(String, Vec<u8>)] {
        &self.files
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
    pub fn allowed_root(&self) -> &Path {
        &self.allowed_root
    }

    pub fn entry(&self) -> &Path {
        &self.entry
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
    walk_dir(&root, &root, 0, &mut files, &mut total_bytes)?;
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
            children.push(entry.path());
        }
        children.sort();
        reject_symlink(path)?;
        for child in children {
            walk_dir(root, &child, depth.saturating_add(1), files, total_bytes)?;
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
    #[cfg(not(unix))]
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
    #[cfg(not(unix))]
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

fn assert_imports_stay_in_root(root: &Path, files: &[(String, Vec<u8>)]) -> Result<()> {
    for (rel, bytes) in files {
        let source = std::str::from_utf8(bytes)
            .map_err(|_| tree_error("module tree file is not valid UTF-8"))?;
        let file_abs = root.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        let parent = file_abs
            .parent()
            .ok_or_else(|| tree_error("module tree walk failed"))?;
        for spec in parse_use_specs(source) {
            if let Some(target) = resolve_use_spec(parent, &spec)
                && !path_is_under(root, &target)
            {
                return Err(tree_error("module import escapes the allowed root"));
            }
        }
    }
    Ok(())
}

fn parse_use_specs(source: &str) -> Vec<String> {
    let mut specs = Vec::new();
    let mut rest = source;
    while let Some(idx) = rest.find("use ") {
        let before = &rest[..idx];
        let boundary = before
            .chars()
            .rev()
            .find(|ch| !ch.is_whitespace())
            .map(|ch| ch == ';' || ch == '{' || ch == '}' || ch == '\n')
            .unwrap_or(true);
        let after = &rest[idx + 4..];
        if boundary && let Some(end) = after.find(';') {
            let raw = after[..end].trim();
            let without_alias = raw.split(" as ").next().unwrap_or(raw).trim();
            let spec = without_alias
                .split('{')
                .next()
                .unwrap_or(without_alias)
                .trim()
                .trim_end_matches("::")
                .trim();
            if !spec.is_empty() {
                specs.push(spec.to_string());
            }
            rest = &after[end + 1..];
            continue;
        }
        rest = after;
    }
    specs
}

fn resolve_use_spec(parent: &Path, spec: &str) -> Option<PathBuf> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    if spec.starts_with('/') || spec.starts_with('\\') {
        return Some(PathBuf::from(spec));
    }
    let path_like = spec.starts_with('.')
        || spec.starts_with("super")
        || spec.starts_with("self")
        || spec.contains('/')
        || spec.contains('\\')
        || spec.ends_with(".rss");
    let module_like = spec.contains("::");
    if !path_like && !module_like {
        return None;
    }
    let mut path = PathBuf::new();
    if spec.contains("::") {
        let mut segments = spec.split("::").peekable();
        while let Some(segment) = segments.peek().copied() {
            match segment {
                "self" => {
                    segments.next();
                }
                "super" => {
                    path.push("..");
                    segments.next();
                }
                "crate" => return Some(parent.join("__escape_crate__")),
                _ => break,
            }
        }
        for segment in segments {
            if segment.is_empty() {
                continue;
            }
            path.push(segment);
        }
    } else {
        path.push(spec);
    }
    if path.as_os_str().is_empty() {
        return None;
    }
    if path.extension().is_none() {
        path.set_extension("rss");
    }
    Some(parent.join(path))
}

fn path_is_under(root: &Path, path: &Path) -> bool {
    let normalized = normalize_components(path);
    let root = normalize_components(root);
    normalized.starts_with(&root)
}

fn normalize_components(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(component),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            Component::Normal(name) => out.push(name),
        }
    }
    out
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

fn compile_temp_root() -> PathBuf {
    std::env::var_os("TEST_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
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
    #[cfg(not(unix))]
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
    if path.exists() {
        reject_symlink(path)?;
        let meta =
            fs::symlink_metadata(path).map_err(|_| tree_error("module compile sandbox failed"))?;
        if !meta.is_dir() {
            return Err(tree_error("module compile sandbox failed"));
        }
        return Ok(());
    }
    create_dir_0700(path).map_err(|_| tree_error("module compile sandbox failed"))
}

fn ensure_parents_0700(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    for component in parent.components() {
        current.push(component);
        ensure_dir_0700(&current)?;
    }
    Ok(())
}

fn create_private_sandbox() -> Result<PathBuf> {
    let root = compile_temp_root();
    ensure_dir_0700(&root).or_else(|_| {
        fs::create_dir_all(&root).map_err(|_| tree_error("module compile sandbox failed"))
    })?;
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
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(tree_error("module compile sandbox failed")),
        }
    }
    Err(tree_error("module compile sandbox failed"))
}

fn materialize_snapshot(snapshot: &ModuleSnapshot) -> Result<MaterializedSnapshot> {
    let sandbox = create_private_sandbox()?;
    let materialized = MaterializedSnapshot {
        sandbox: sandbox.clone(),
        allowed_root: sandbox.join(SANDBOX_TREE_DIR),
        entry: sandbox.join(SANDBOX_TREE_DIR).join(
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
    ensure_dir_0700(&materialized.allowed_root)?;
    for (rel, bytes) in &snapshot.files {
        assert_safe_rel(rel)?;
        let dest = materialized
            .allowed_root
            .join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        if !dest.starts_with(&materialized.allowed_root) {
            return Err(tree_error("module compile sandbox failed"));
        }
        ensure_parents_0700(&dest)?;
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
            assert!(sandbox_path.starts_with(compile_temp_root()));
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
        assert_eq!(
            error.to_string(),
            "RustScript compile error: module import escapes the allowed root"
        );
        assert!(!error.to_string().contains(root.to_string_lossy().as_ref()));
        let _ = fs::remove_dir_all(&root);
    }
}
