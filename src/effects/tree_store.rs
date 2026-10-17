//! Private directory copies for Native effect trees.
//!
//! Numbered cancellation checks run once before the copy phase and once before
//! each planned entry, in sorted relative-path order. The scan does not consume
//! those checks, so a caller can cancel or mutate the source at a stable point.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use parking_lot::Mutex;

use super::types::{
    EffectCancellation, EffectDeadline, EffectError, EffectErrorKind, MAX_COMPONENT_BYTES,
    MAX_RELATIVE_BYTES, ResourceQuota,
};

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Usage {
    pub(crate) entries: u64,
    pub(crate) bytes: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TreeCopy {
    pub(crate) entries: u64,
    pub(crate) bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileKind {
    File,
    Dir,
    Symlink,
    Special,
}

struct Stamp {
    len: u64,
    executable: bool,
}

struct PlanEntry {
    rel: String,
    components: Vec<OsString>,
    kind: PlanKind,
    stamp: Stamp,
}

enum PlanKind {
    Dir,
    File,
}

struct Plan {
    entries: Vec<PlanEntry>,
    inodes: std::collections::HashMap<(u64, u64), (u64, u64)>,
    entries_count: u64,
    bytes: u64,
}

pub(crate) struct WorkRoot {
    path: PathBuf,
    dir: OwnedFd,
    quota: ResourceQuota,
    usage: Mutex<Usage>,
}

impl WorkRoot {
    pub(crate) fn open(
        path: PathBuf,
        quota: ResourceQuota,
        usage: Usage,
    ) -> Result<Self, EffectError> {
        let dir = open_dir(&path)?;
        Ok(Self {
            path,
            dir,
            quota,
            usage: Mutex::new(usage),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn write_file(&self, rel: &str, bytes: &[u8]) -> Result<(), EffectError> {
        let components = validate_relative(rel)?;
        self.ensure_depth(&components)?;
        let parent = self.open_parent(&components)?;
        let name = components.last().expect("relative path has a component");
        let old = match stat_at(&parent, name) {
            Ok(stat) => {
                reject_special(&stat, "write")?;
                if file_kind(stat.st_mode) != FileKind::File {
                    return Err(unsupported("write target is not a regular file"));
                }
                Some(file_len(stat)?)
            }
            Err(error) if error.kind() == EffectErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let mut usage = self.usage.lock();
        let next_entries = usage.entries + u64::from(old.is_none());
        let next_bytes = usage.bytes - old.unwrap_or(0) + bytes.len() as u64;
        if next_entries > self.quota.max_entries || next_bytes > self.quota.max_bytes {
            return Err(quota_error("view write exceeds quota"));
        }
        let mode = 0o644;
        let fd = if old.is_some() {
            open_trunc(&parent, name)?
        } else {
            create_file(&parent, name, mode)?
        };
        write_all(&fd, bytes)?;
        fsync_fd(&fd)?;
        usage.entries = next_entries;
        usage.bytes = next_bytes;
        Ok(())
    }

    pub(crate) fn read_file(&self, rel: &str) -> Result<Vec<u8>, EffectError> {
        read_from(&self.dir, rel)
    }

    pub(crate) fn delete(&self, rel: &str) -> Result<(), EffectError> {
        let components = validate_relative(rel)?;
        let parent = self.open_parent(&components)?;
        let name = components.last().expect("relative path has a component");
        let stat = stat_at(&parent, name)?;
        reject_special(&stat, "delete")?;
        let removed_bytes = match file_kind(stat.st_mode) {
            FileKind::File => {
                unlink_at(&parent, name, false)?;
                file_len(stat)?
            }
            FileKind::Dir => {
                if !dir_is_empty(&parent, name)? {
                    return Err(io_error(
                        "delete",
                        io::Error::from_raw_os_error(libc::ENOTEMPTY),
                    ));
                }
                unlink_at(&parent, name, true)?;
                0
            }
            FileKind::Symlink | FileKind::Special => {
                return Err(unsupported("refusing to delete a symlink or special file"));
            }
        };
        let mut usage = self.usage.lock();
        usage.entries = usage.entries.saturating_sub(1);
        usage.bytes = usage.bytes.saturating_sub(removed_bytes);
        Ok(())
    }

    pub(crate) fn rename(&self, from: &str, to: &str) -> Result<(), EffectError> {
        let from_parts = validate_relative(from)?;
        let to_parts = validate_relative(to)?;
        self.ensure_depth(&to_parts)?;
        if stat_relative(&self.dir, &to_parts).is_ok() {
            return Err(io_error(
                "rename",
                io::Error::from_raw_os_error(libc::EEXIST),
            ));
        }
        let from_parent = self.open_parent(&from_parts)?;
        let to_parent = self.open_parent(&to_parts)?;
        let from_name = c_name(from_parts.last().expect("from component"))?;
        let to_name = c_name(to_parts.last().expect("to component"))?;
        let rc = unsafe {
            libc::renameat(
                from_parent.as_raw_fd(),
                from_name.as_ptr(),
                to_parent.as_raw_fd(),
                to_name.as_ptr(),
            )
        };
        if rc < 0 {
            Err(from_errno("rename", errno()))
        } else {
            Ok(())
        }
    }

    pub(crate) fn create_dir(&self, rel: &str) -> Result<(), EffectError> {
        let components = validate_relative(rel)?;
        self.ensure_depth(&components)?;
        let parent = self.open_parent(&components)?;
        let name = components.last().expect("relative path has a component");
        let mut usage = self.usage.lock();
        if usage.entries + 1 > self.quota.max_entries {
            return Err(quota_error("directory exceeds entry quota"));
        }
        mkdir_at(&parent, name)?;
        usage.entries += 1;
        Ok(())
    }

    pub(crate) fn set_executable(&self, rel: &str, executable: bool) -> Result<(), EffectError> {
        let components = validate_relative(rel)?;
        let parent = self.open_parent(&components)?;
        let name = components.last().expect("relative path has a component");
        let stat = stat_at(&parent, name)?;
        reject_special(&stat, "chmod")?;
        if file_kind(stat.st_mode) != FileKind::File {
            return Err(unsupported("executable bit is only for regular files"));
        }
        let fd = open_read(&parent, name)?;
        let mode = if executable { 0o755 } else { 0o644 };
        let rc = unsafe { libc::fchmod(fd.as_raw_fd(), mode) };
        if rc < 0 {
            Err(from_errno("fchmod", errno()))
        } else {
            Ok(())
        }
    }

    pub(crate) fn list(&self, rel: &str) -> Result<Vec<String>, EffectError> {
        let dir = if rel.is_empty() {
            dup_dir(&self.dir)?
        } else {
            open_existing_dir(&self.dir, &validate_relative(rel)?)?
        };
        let names = read_names(&dir)?;
        let mut listed = Vec::new();
        for name in names {
            let text = name
                .to_str()
                .ok_or_else(|| rejected("directory entry is not utf-8"))?
                .to_string();
            listed.push(text);
        }
        listed.sort();
        Ok(listed)
    }

    fn ensure_depth(&self, components: &[String]) -> Result<(), EffectError> {
        if components.len() as u32 > self.quota.max_depth {
            Err(quota_error("path exceeds depth quota"))
        } else {
            Ok(())
        }
    }

    fn open_parent(&self, components: &[String]) -> Result<OwnedFd, EffectError> {
        if components.len() == 1 {
            return dup_dir(&self.dir);
        }
        open_existing_dir(&self.dir, &components[..components.len() - 1])
    }
}

pub(crate) fn copy_tree(
    source: &Path,
    dest: &Path,
    quota: &ResourceQuota,
    cancellation: &EffectCancellation,
    deadline: &EffectDeadline,
    seal: bool,
) -> Result<TreeCopy, EffectError> {
    deadline.check()?;
    cancellation.poll()?;
    let source_stat = lstat_path(source)?;
    if file_kind(source_stat.st_mode) != FileKind::Dir {
        return Err(unsupported("import source is not a real directory"));
    }
    let source_dir = open_dir(source)?;
    let mut plan = scan(&source_dir, quota, deadline, cancellation)?;
    plan.entries.sort_by(|left, right| left.rel.cmp(&right.rel));
    fs::create_dir(dest).map_err(|error| io_error("create copy", error))?;
    let guard = RemoveGuard {
        path: dest.to_path_buf(),
        armed: true,
    };
    let dest_dir = open_dir(dest)?;
    materialize(&source_dir, &dest_dir, &plan, cancellation, deadline, seal)?;
    verify_unchanged(&source_dir, &dest_dir, &plan)?;
    fsync_fd(&dest_dir)?;
    guard.keep();
    Ok(TreeCopy {
        entries: plan.entries_count,
        bytes: plan.bytes,
    })
}

pub(crate) fn read_from(root: &OwnedFd, rel: &str) -> Result<Vec<u8>, EffectError> {
    let components = validate_relative(rel)?;
    let parent = if components.len() == 1 {
        dup_dir(root)?
    } else {
        open_existing_dir(root, &components[..components.len() - 1])?
    };
    let name = components.last().expect("relative path has a component");
    let stat = stat_at(&parent, name)?;
    reject_special(&stat, "read")?;
    if file_kind(stat.st_mode) != FileKind::File {
        return Err(unsupported("read target is not a regular file"));
    }
    let len = file_len(stat)?;
    if len > super::types::MAX_TREE_BYTES {
        return Err(quota_error("file exceeds the hard byte ceiling"));
    }
    let fd = open_read(&parent, name)?;
    read_fd(&fd, len as usize)
}

pub(crate) fn remove_tree(path: &Path) -> Result<(), EffectError> {
    match lstat_path(path) {
        Err(error) if error.kind() == EffectErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(stat) => match file_kind(stat.st_mode) {
            FileKind::Dir => {
                let dir = open_dir(path)?;
                remove_children(&dir)?;
                fs::remove_dir(path).map_err(|error| io_error("remove directory", error))
            }
            _ => fs::remove_file(path).map_err(|error| io_error("remove path", error)),
        },
    }
}

pub(crate) fn fsync_dir(path: &Path) -> Result<(), EffectError> {
    let dir = open_dir(path)?;
    fsync_fd(&dir)
}

pub(crate) fn chmod_dir(path: &Path, mode: u32) -> Result<(), EffectError> {
    let dir = open_dir(path)?;
    let rc = unsafe { libc::fchmod(dir.as_raw_fd(), mode) };
    if rc < 0 {
        Err(from_errno("fchmod", errno()))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_relative(path: &str) -> Result<Vec<String>, EffectError> {
    if path.is_empty()
        || path.len() > MAX_RELATIVE_BYTES
        || path.starts_with('/')
        || path.as_bytes().contains(&b'\\')
        || path.as_bytes().contains(&0)
    {
        return Err(rejected(
            "path is absolute, empty, or contains a forbidden byte",
        ));
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.ends_with('.')
            || component.len() > MAX_COMPONENT_BYTES
            || component.as_bytes().iter().any(|byte| *byte < 0x20)
        {
            return Err(rejected("path component is not allowed"));
        }
        components.push(component.to_string());
    }
    Ok(components)
}

struct RemoveGuard {
    path: PathBuf,
    armed: bool,
}

impl RemoveGuard {
    fn keep(mut self) {
        self.armed = false;
    }
}

impl Drop for RemoveGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_tree(&self.path);
        }
    }
}

fn scan(
    root: &OwnedFd,
    quota: &ResourceQuota,
    deadline: &EffectDeadline,
    cancellation: &EffectCancellation,
) -> Result<Plan, EffectError> {
    let mut plan = Plan {
        entries: Vec::new(),
        inodes: std::collections::HashMap::new(),
        entries_count: 0,
        bytes: 0,
    };
    scan_dir(root, "", 0, quota, deadline, cancellation, &mut plan)?;
    for ((_, _), (nlink, seen)) in &plan.inodes {
        if *nlink > *seen {
            return Err(unsupported("external hardlink is not importable"));
        }
        if *seen > *nlink {
            return Err(inconsistent("hardlink count changed during scan"));
        }
    }
    Ok(plan)
}

fn scan_dir(
    dir: &OwnedFd,
    prefix: &str,
    depth: u32,
    quota: &ResourceQuota,
    deadline: &EffectDeadline,
    cancellation: &EffectCancellation,
    plan: &mut Plan,
) -> Result<(), EffectError> {
    deadline.check()?;
    cancellation.poll_quiet()?;
    for name in read_names(dir)? {
        let text = name
            .to_str()
            .ok_or_else(|| rejected("directory entry is not utf-8"))?;
        if text.len() > MAX_COMPONENT_BYTES || text.ends_with('.') || text.contains('\0') {
            return Err(rejected("directory entry name is not allowed"));
        }
        let rel = if prefix.is_empty() {
            text.to_string()
        } else {
            format!("{prefix}/{text}")
        };
        if rel.len() > MAX_RELATIVE_BYTES {
            return Err(rejected("relative path is too long"));
        }
        let next_depth = depth + 1;
        if next_depth > quota.max_depth {
            return Err(quota_error("tree exceeds depth quota"));
        }
        let stat = stat_at(dir, text)?;
        let mut components = Vec::new();
        if !prefix.is_empty() {
            components.extend(prefix.split('/').map(OsString::from));
        }
        components.push(name.clone());
        match file_kind(stat.st_mode) {
            FileKind::Symlink => return Err(unsupported("symlink is not importable")),
            FileKind::Special => return Err(unsupported("special file is not importable")),
            FileKind::Dir => {
                account_entry(plan, quota, 0)?;
                plan.entries.push(PlanEntry {
                    rel: rel.clone(),
                    components,
                    kind: PlanKind::Dir,
                    stamp: Stamp {
                        len: 0,
                        executable: true,
                    },
                });
                let child = open_child_dir(dir, text)?;
                scan_dir(
                    &child,
                    &rel,
                    next_depth,
                    quota,
                    deadline,
                    cancellation,
                    plan,
                )?;
            }
            FileKind::File => {
                let len = file_len(stat)?;
                account_entry(plan, quota, len)?;
                let key = (stat_u64(stat.st_dev), stat_u64(stat.st_ino));
                let slot = plan.inodes.entry(key).or_insert((stat.st_nlink as u64, 0));
                slot.1 += 1;
                plan.entries.push(PlanEntry {
                    rel,
                    components,
                    kind: PlanKind::File,
                    stamp: Stamp {
                        len,
                        executable: stat.st_mode & 0o111 != 0,
                    },
                });
            }
        }
    }
    Ok(())
}

fn account_entry(plan: &mut Plan, quota: &ResourceQuota, bytes: u64) -> Result<(), EffectError> {
    plan.entries_count += 1;
    plan.bytes += bytes;
    if plan.entries_count > quota.max_entries || plan.bytes > quota.max_bytes {
        Err(quota_error("tree exceeds quota"))
    } else {
        Ok(())
    }
}

fn materialize(
    source: &OwnedFd,
    dest: &OwnedFd,
    plan: &Plan,
    cancellation: &EffectCancellation,
    deadline: &EffectDeadline,
    seal: bool,
) -> Result<(), EffectError> {
    for entry in &plan.entries {
        deadline.check()?;
        cancellation.poll()?;
        match entry.kind {
            PlanKind::Dir => {
                let parent = parent_fd(dest, &entry.components)?;
                let name = entry
                    .components
                    .last()
                    .and_then(|component| component.to_str())
                    .expect("utf-8 directory name");
                mkdir_at(&parent, name)?;
            }
            PlanKind::File => copy_planned_file(source, dest, entry, seal)?,
        }
    }
    if seal {
        seal_directories(dest, plan)?;
    }
    Ok(())
}

fn copy_planned_file(
    source: &OwnedFd,
    dest: &OwnedFd,
    entry: &PlanEntry,
    seal: bool,
) -> Result<(), EffectError> {
    let source_parent = parent_fd(source, &entry.components)?;
    let dest_parent = parent_fd(dest, &entry.components)?;
    let name = entry
        .components
        .last()
        .expect("file component")
        .to_str()
        .expect("utf-8 file name");
    let stat = stat_at(&source_parent, name)?;
    if file_kind(stat.st_mode) != FileKind::File || file_len(stat)? != entry.stamp.len {
        return Err(inconsistent("source file changed before copy"));
    }
    let readable = open_read(&source_parent, name)?;
    let bytes = read_fd(&readable, entry.stamp.len as usize)?;
    let mode = if seal {
        if entry.stamp.executable { 0o555 } else { 0o444 }
    } else if entry.stamp.executable {
        0o755
    } else {
        0o644
    };
    let created = create_file(&dest_parent, name, mode)?;
    write_all(&created, &bytes)?;
    fchmod_fd(&created, mode)?;
    fsync_fd(&created)?;
    Ok(())
}

fn seal_directories(dest: &OwnedFd, plan: &Plan) -> Result<(), EffectError> {
    for entry in &plan.entries {
        if !matches!(entry.kind, PlanKind::Dir) {
            continue;
        }
        let parent = parent_fd(dest, &entry.components)?;
        let name = entry
            .components
            .last()
            .and_then(|component| component.to_str())
            .ok_or_else(|| inconsistent("directory name disappeared"))?;
        let created = open_child_dir(&parent, name)?;
        fchmod_fd(&created, 0o555)?;
    }
    Ok(())
}

fn verify_unchanged(source: &OwnedFd, dest: &OwnedFd, plan: &Plan) -> Result<(), EffectError> {
    for entry in &plan.entries {
        if !matches!(entry.kind, PlanKind::File) {
            continue;
        }
        let name = entry
            .components
            .last()
            .and_then(|name| name.to_str())
            .ok_or_else(|| inconsistent("planned name disappeared"))?;
        let source_parent = parent_fd(source, &entry.components)?;
        let dest_parent = parent_fd(dest, &entry.components)?;
        let source_bytes = read_named(&source_parent, name)?;
        let dest_bytes = read_named(&dest_parent, name)?;
        if source_bytes != dest_bytes {
            return Err(inconsistent("source changed during copy"));
        }
    }
    Ok(())
}

fn read_named(parent: &OwnedFd, name: &str) -> Result<Vec<u8>, EffectError> {
    let stat = stat_at(parent, name).map_err(|_| inconsistent("source entry disappeared"))?;
    if file_kind(stat.st_mode) != FileKind::File {
        return Err(inconsistent("source entry changed type"));
    }
    let fd = open_read(parent, name)?;
    read_fd(&fd, file_len(stat)? as usize)
}

fn parent_fd(root: &OwnedFd, components: &[OsString]) -> Result<OwnedFd, EffectError> {
    if components.len() <= 1 {
        return dup_dir(root);
    }
    let mut current = dup_dir(root)?;
    for component in &components[..components.len() - 1] {
        let name = component
            .to_str()
            .ok_or_else(|| rejected("component is not utf-8"))?;
        current = open_child_dir(&current, name)?;
    }
    Ok(current)
}

fn open_existing_dir(root: &OwnedFd, components: &[String]) -> Result<OwnedFd, EffectError> {
    let mut current = dup_dir(root)?;
    for component in components {
        current = open_child_dir(&current, component)?;
    }
    Ok(current)
}

fn stat_relative(root: &OwnedFd, components: &[String]) -> Result<libc::stat, EffectError> {
    let parent = if components.len() == 1 {
        dup_dir(root)?
    } else {
        open_existing_dir(root, &components[..components.len() - 1])?
    };
    stat_at(&parent, components.last().expect("component"))
}

fn remove_children(dir: &OwnedFd) -> Result<(), EffectError> {
    for name in read_names(dir)? {
        let text = name
            .to_str()
            .ok_or_else(|| rejected("directory entry is not utf-8"))?;
        let stat = stat_at(dir, text)?;
        match file_kind(stat.st_mode) {
            FileKind::Dir => {
                let child = open_child_dir(dir, text)?;
                remove_children(&child)?;
                unlink_at(dir, text, true)?;
            }
            _ => unlink_at(dir, text, false)?,
        }
    }
    Ok(())
}

fn dir_is_empty(parent: &OwnedFd, name: &str) -> Result<bool, EffectError> {
    let child = open_child_dir(parent, name)?;
    Ok(read_names(&child)?.is_empty())
}

fn read_names(dir: &OwnedFd) -> Result<Vec<OsString>, EffectError> {
    let dup_fd = unsafe { libc::dup(dir.as_raw_fd()) };
    if dup_fd < 0 {
        return Err(from_errno("dup", errno()));
    }
    let stream = unsafe { libc::fdopendir(dup_fd) };
    if stream.is_null() {
        let code = errno();
        unsafe { libc::close(dup_fd) };
        return Err(from_errno("fdopendir", code));
    }
    let mut names = Vec::new();
    loop {
        clear_errno();
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let code = errno();
            unsafe { libc::closedir(stream) };
            if code != 0 {
                return Err(from_errno("readdir", code));
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        names.push(OsStr::from_bytes(bytes).to_os_string());
    }
    names.sort();
    Ok(names)
}

fn open_dir(path: &Path) -> Result<OwnedFd, EffectError> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| rejected("path contains an interior NUL"))?;
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    owned_fd(fd, "open directory")
}

fn dup_dir(dir: &OwnedFd) -> Result<OwnedFd, EffectError> {
    let fd = unsafe { libc::dup(dir.as_raw_fd()) };
    owned_fd(fd, "dup")
}

fn open_child_dir(parent: &OwnedFd, name: &str) -> Result<OwnedFd, EffectError> {
    let c_name = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    owned_fd(fd, "open child directory")
}

fn open_read(parent: &OwnedFd, name: &str) -> Result<OwnedFd, EffectError> {
    let c_name = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    owned_fd(fd, "open file")
}

fn open_trunc(parent: &OwnedFd, name: &str) -> Result<OwnedFd, EffectError> {
    let c_name = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_WRONLY | libc::O_TRUNC | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    owned_fd(fd, "truncate file")
}

fn create_file(parent: &OwnedFd, name: &str, mode: u32) -> Result<OwnedFd, EffectError> {
    let c_name = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    owned_fd(fd, "create file")
}

fn mkdir_at(parent: &OwnedFd, name: &str) -> Result<(), EffectError> {
    let c_name = c_name(name)?;
    let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), c_name.as_ptr(), 0o755) };
    if rc < 0 {
        Err(from_errno("mkdir", errno()))
    } else {
        Ok(())
    }
}

fn unlink_at(parent: &OwnedFd, name: &str, directory: bool) -> Result<(), EffectError> {
    let c_name = c_name(name)?;
    let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
    let rc = unsafe { libc::unlinkat(parent.as_raw_fd(), c_name.as_ptr(), flags) };
    if rc < 0 {
        Err(from_errno("unlink", errno()))
    } else {
        Ok(())
    }
}

fn stat_at(parent: &OwnedFd, name: &str) -> Result<libc::stat, EffectError> {
    let c_name = c_name(name)?;
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            c_name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc < 0 {
        Err(from_errno("fstatat", errno()))
    } else {
        Ok(unsafe { stat.assume_init() })
    }
}

fn lstat_path(path: &Path) -> Result<libc::stat, EffectError> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| rejected("path contains an interior NUL"))?;
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe { libc::lstat(c_path.as_ptr(), stat.as_mut_ptr()) };
    if rc < 0 {
        Err(from_errno("lstat", errno()))
    } else {
        Ok(unsafe { stat.assume_init() })
    }
}

fn write_all(fd: &OwnedFd, bytes: &[u8]) -> Result<(), EffectError> {
    let mut offset = 0;
    while offset < bytes.len() {
        let wrote = unsafe {
            libc::write(
                fd.as_raw_fd(),
                bytes[offset..].as_ptr().cast::<libc::c_void>(),
                bytes.len() - offset,
            )
        };
        if wrote < 0 {
            let code = errno();
            if code == libc::EINTR {
                continue;
            }
            return Err(from_errno("write", code));
        }
        offset += wrote as usize;
    }
    Ok(())
}

fn read_fd(fd: &OwnedFd, len: usize) -> Result<Vec<u8>, EffectError> {
    let mut bytes = vec![0_u8; len];
    let mut offset = 0;
    while offset < len {
        let read = unsafe {
            libc::read(
                fd.as_raw_fd(),
                bytes[offset..].as_mut_ptr().cast::<libc::c_void>(),
                len - offset,
            )
        };
        if read < 0 {
            let code = errno();
            if code == libc::EINTR {
                continue;
            }
            return Err(from_errno("read", code));
        }
        if read == 0 {
            break;
        }
        offset += read as usize;
    }
    bytes.truncate(offset);
    Ok(bytes)
}

fn fsync_fd(fd: &OwnedFd) -> Result<(), EffectError> {
    let rc = unsafe { libc::fsync(fd.as_raw_fd()) };
    if rc < 0 {
        Err(from_errno("fsync", errno()))
    } else {
        Ok(())
    }
}

fn fchmod_fd(fd: &OwnedFd, mode: u32) -> Result<(), EffectError> {
    let rc = unsafe { libc::fchmod(fd.as_raw_fd(), mode) };
    if rc < 0 {
        Err(from_errno("fchmod", errno()))
    } else {
        Ok(())
    }
}

fn owned_fd(fd: i32, operation: &str) -> Result<OwnedFd, EffectError> {
    if fd < 0 {
        Err(from_errno(operation, errno()))
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn c_name(name: &str) -> Result<CString, EffectError> {
    CString::new(name.as_bytes()).map_err(|_| rejected("component contains NUL"))
}

fn file_kind(mode: libc::mode_t) -> FileKind {
    match mode & libc::S_IFMT {
        libc::S_IFREG => FileKind::File,
        libc::S_IFDIR => FileKind::Dir,
        libc::S_IFLNK => FileKind::Symlink,
        _ => FileKind::Special,
    }
}

fn reject_special(stat: &libc::stat, operation: &str) -> Result<(), EffectError> {
    match file_kind(stat.st_mode) {
        FileKind::Symlink => Err(unsupported(format!("{operation} target is a symlink"))),
        FileKind::Special => Err(unsupported(format!("{operation} target is a special file"))),
        FileKind::File | FileKind::Dir => Ok(()),
    }
}

fn file_len(stat: libc::stat) -> Result<u64, EffectError> {
    if stat.st_size < 0 {
        Err(unsupported("file size is negative"))
    } else {
        Ok(stat.st_size as u64)
    }
}

fn stat_u64(value: u64) -> u64 {
    value
}

fn clear_errno() {
    unsafe {
        *libc::__errno_location() = 0;
    }
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn from_errno(operation: &str, code: i32) -> EffectError {
    let kind = match code {
        libc::ENOENT => EffectErrorKind::NotFound,
        libc::ELOOP => EffectErrorKind::UnsupportedEntry,
        libc::ENAMETOOLONG => EffectErrorKind::RejectedPath,
        _ => EffectErrorKind::Io,
    };
    EffectError::new(kind, format!("{operation} failed with errno {code}"))
}

fn io_error(operation: &str, error: io::Error) -> EffectError {
    from_errno(operation, error.raw_os_error().unwrap_or(0))
}

fn rejected(message: impl Into<String>) -> EffectError {
    EffectError::new(EffectErrorKind::RejectedPath, message)
}

fn unsupported(message: impl Into<String>) -> EffectError {
    EffectError::new(EffectErrorKind::UnsupportedEntry, message)
}

fn quota_error(message: impl Into<String>) -> EffectError {
    EffectError::new(EffectErrorKind::QuotaExceeded, message)
}

fn inconsistent(message: impl Into<String>) -> EffectError {
    EffectError::new(EffectErrorKind::InconsistentSource, message)
}
