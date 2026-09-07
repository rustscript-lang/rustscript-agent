//! Frozen-dirfd range I/O and cursor listing for capability filesystem primitives.
//!
//! The pinned RustScript `ConfinedFile` type exposes no public raw fd or
//! bounded-window read, and `enumerate_with_budget` errors instead of paging.
//! This module opens the workspace directory once at admission and later
//! resolves relative paths with Linux `openat2` (beneath / no-magic-link /
//! no-symlink) or a Unix `openat` + `O_NOFOLLOW` component walk. Reads use
//! `FileExt::read_at` so the transferred byte count is the requested window.
//! Listing streams `readdir` with a skip cursor, page limit, and one-entry
//! lookahead. Non-Unix targets fail closed.

use std::path::Path;

use super::types::CapabilityError;

const MAX_PATH_BYTES: usize = 4096;
const MAX_COMPONENT_BYTES: usize = 255;

/// Directory descriptor retained at capability admission.
pub(crate) struct FrozenDir {
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
}

/// Bytes read from an admitted window plus the opened file's length.
pub(crate) struct RangeBytes {
    pub bytes: Vec<u8>,
    pub file_len: u64,
}

/// One streamed directory entry.
pub(crate) struct ListEntry {
    pub name: String,
    pub file_type: &'static str,
    pub len: u64,
}

/// One cursor page. Only `limit` entries are retained, plus constant lookahead.
pub(crate) struct ListPage {
    pub entries: Vec<ListEntry>,
    pub next_cursor: u64,
    pub truncated: bool,
}

impl FrozenDir {
    /// Opens and retains `path` as a directory descriptor. The path is not
    /// reopened for later reads.
    pub(crate) fn open(path: &Path) -> Result<Self, CapabilityError> {
        #[cfg(unix)]
        {
            unix::open_root(path)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(unsupported())
        }
    }

    /// Reads at most `limit` bytes starting at `offset` through the frozen fd.
    pub(crate) fn read_range(
        &self,
        path: &str,
        offset: u64,
        limit: usize,
    ) -> Result<RangeBytes, CapabilityError> {
        #[cfg(unix)]
        {
            unix::read_range(self, path, offset, limit)
        }
        #[cfg(not(unix))]
        {
            let _ = (self, path, offset, limit);
            Err(unsupported())
        }
    }

    /// Returns up to `limit` entries after skipping `cursor` names.
    pub(crate) fn list_page(
        &self,
        path: &str,
        cursor: u64,
        limit: usize,
    ) -> Result<ListPage, CapabilityError> {
        #[cfg(unix)]
        {
            unix::list_page(self, path, cursor, limit)
        }
        #[cfg(not(unix))]
        {
            let _ = (self, path, cursor, limit);
            Err(unsupported())
        }
    }
}

#[cfg(not(unix))]
fn unsupported() -> CapabilityError {
    CapabilityError::new(
        "unsupported_platform",
        "confined range I/O requires a Unix directory descriptor",
    )
}

fn path_denied(message: &str) -> CapabilityError {
    CapabilityError::new("path_denied", message)
}

fn validate_file_path(path: &str) -> Result<Vec<&str>, CapabilityError> {
    if path.is_empty() {
        return Err(CapabilityError::new(
            "invalid_path",
            "empty paths are not valid file paths",
        ));
    }
    validate_components(path, false)
}

fn validate_dir_path(path: &str) -> Result<Vec<&str>, CapabilityError> {
    validate_components(path, true)
}

fn validate_components(path: &str, allow_empty: bool) -> Result<Vec<&str>, CapabilityError> {
    if path.is_empty() {
        if allow_empty {
            return Ok(Vec::new());
        }
        return Err(CapabilityError::new(
            "invalid_path",
            "empty paths are not valid file paths",
        ));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(path_denied("relative path exceeds the hard bound"));
    }
    if path.as_bytes().contains(&0) {
        return Err(path_denied("path contains a NUL byte"));
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(path_denied(
            "rooted or trailing-separator paths are not permitted",
        ));
    }
    if path.contains('\\') {
        return Err(path_denied("backslash is not a permitted path separator"));
    }
    if path.contains(':') {
        return Err(path_denied("drive and prefix syntax is not permitted"));
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        if component.is_empty() {
            return Err(path_denied("empty path components are not permitted"));
        }
        if component == "." || component == ".." {
            return Err(path_denied("dot and parent components are not permitted"));
        }
        if component.ends_with('.') {
            return Err(path_denied("trailing-dot components are not permitted"));
        }
        if component.len() > MAX_COMPONENT_BYTES {
            return Err(path_denied("path component exceeds the hard bound"));
        }
        components.push(component);
    }
    Ok(components)
}

#[cfg(unix)]
mod unix {
    use std::{
        ffi::CString,
        fs::File,
        io,
        mem::MaybeUninit,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
            unix::{ffi::OsStrExt, fs::FileExt},
        },
        path::Path,
    };

    use super::{
        FrozenDir, ListEntry, ListPage, MAX_COMPONENT_BYTES, RangeBytes, path_denied,
        validate_dir_path, validate_file_path,
    };
    use crate::capabilities::types::CapabilityError;

    pub(super) fn open_root(path: &Path) -> Result<FrozenDir, CapabilityError> {
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| path_denied("workspace path contains a NUL byte"))?;
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(map_io("fs::root", io::Error::last_os_error()));
        }
        Ok(FrozenDir {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    pub(super) fn read_range(
        root: &FrozenDir,
        path: &str,
        offset: u64,
        limit: usize,
    ) -> Result<RangeBytes, CapabilityError> {
        let components = validate_file_path(path)?;
        let fd = open_relative(root.fd.as_raw_fd(), &components, libc::O_RDONLY)?;
        let file = File::from(fd);
        let stat = fstat(file.as_raw_fd())?;
        let mode = stat.st_mode as libc::mode_t;
        if mode & libc::S_IFMT == libc::S_IFLNK {
            return Err(path_denied("symlinks are not followed"));
        }
        if mode & libc::S_IFMT != libc::S_IFREG {
            return Err(CapabilityError::new(
                "wrong_type",
                "path is not a regular file",
            ));
        }
        if stat_u64(stat.st_nlink) > 1 {
            return Err(path_denied("hard links are not permitted"));
        }
        let file_len = stat_u64(stat.st_size);
        if limit == 0 || offset >= file_len {
            return Ok(RangeBytes {
                bytes: Vec::new(),
                file_len,
            });
        }
        let remaining = file_len - offset;
        let want = remaining.min(u64::try_from(limit).unwrap_or(u64::MAX));
        let want = usize::try_from(want).unwrap_or(usize::MAX);
        let mut bytes = vec![0_u8; want];
        let read = file
            .read_at(&mut bytes, offset)
            .map_err(|error| map_io("fs::read", error))?;
        bytes.truncate(read);
        Ok(RangeBytes { bytes, file_len })
    }

    pub(super) fn list_page(
        root: &FrozenDir,
        path: &str,
        cursor: u64,
        limit: usize,
    ) -> Result<ListPage, CapabilityError> {
        let skip = match usize::try_from(cursor) {
            Ok(skip) if skip != usize::MAX => skip,
            _ => {
                return Ok(ListPage {
                    entries: Vec::new(),
                    next_cursor: cursor,
                    truncated: false,
                });
            }
        };
        let components = validate_dir_path(path)?;
        let directory = open_relative(
            root.fd.as_raw_fd(),
            &components,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        stream_page(directory, skip, limit, cursor)
    }

    fn stream_page(
        directory: OwnedFd,
        skip: usize,
        limit: usize,
        cursor: u64,
    ) -> Result<ListPage, CapabilityError> {
        use std::ffi::CStr;
        use std::os::fd::IntoRawFd;

        let raw = directory.into_raw_fd();
        let stream = unsafe { libc::fdopendir(raw) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            unsafe { libc::close(raw) };
            return Err(map_io("fs::enumerate", error));
        }
        let guard = DirGuard(stream);
        let directory_fd = unsafe { libc::dirfd(guard.0) };
        if directory_fd < 0 {
            return Err(map_io("fs::enumerate", io::Error::last_os_error()));
        }
        let mut skipped = 0usize;
        let mut entries = Vec::new();
        let mut truncated = false;
        loop {
            clear_errno();
            let entry = unsafe { libc::readdir(guard.0) };
            if entry.is_null() {
                classify_readdir_end(errno_abi())?;
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            let name_bytes = name.to_bytes();
            if name_bytes == b"." || name_bytes == b".." {
                continue;
            }
            if name_bytes.len() > MAX_COMPONENT_BYTES {
                return Err(CapabilityError::new(
                    "budget_exceeded",
                    "directory entry name budget exceeded",
                ));
            }
            if skipped < skip {
                skipped += 1;
                continue;
            }
            if entries.len() >= limit {
                truncated = true;
                break;
            }
            let (file_type, len) = match metadata_at(directory_fd, name_bytes) {
                Ok(meta) => meta,
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => continue,
                Err(error) => return Err(map_io("fs::enumerate", error)),
            };
            entries.push(ListEntry {
                name: String::from_utf8_lossy(name_bytes).into_owned(),
                file_type,
                len,
            });
        }
        Ok(ListPage {
            next_cursor: cursor.saturating_add(entries.len() as u64),
            truncated,
            entries,
        })
    }

    fn metadata_at(directory_fd: RawFd, name: &[u8]) -> Result<(&'static str, u64), io::Error> {
        let name = CString::new(name).expect("validated component contains no NUL");
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                directory_fd,
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        let mode = stat.st_mode as libc::mode_t;
        let file_type = match mode & libc::S_IFMT {
            libc::S_IFREG => "file",
            libc::S_IFDIR => "directory",
            libc::S_IFLNK => "symlink",
            _ => "other",
        };
        Ok((file_type, stat_u64(stat.st_size)))
    }

    fn clear_errno() {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        unsafe {
            *libc::__errno_location() = 0;
        }
        #[cfg(any(
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "ios",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        unsafe {
            *libc::__error() = 0;
        }
    }

    enum ErrnoAbi {
        Known(i32),
        #[allow(dead_code)]
        Unsupported,
    }

    fn errno_abi() -> ErrnoAbi {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            ErrnoAbi::Known(unsafe { *libc::__errno_location() })
        }
        #[cfg(any(
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "ios",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        {
            ErrnoAbi::Known(unsafe { *libc::__error() })
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "ios",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd"
        )))]
        {
            ErrnoAbi::Unsupported
        }
    }

    fn classify_readdir_end(errno: ErrnoAbi) -> Result<(), CapabilityError> {
        match errno {
            ErrnoAbi::Known(0) => Ok(()),
            ErrnoAbi::Known(code) => {
                Err(map_io("fs::enumerate", io::Error::from_raw_os_error(code)))
            }
            ErrnoAbi::Unsupported => Err(CapabilityError::new(
                "unsupported_platform",
                "readdir errno is unavailable on this target",
            )),
        }
    }

    struct DirGuard(*mut libc::DIR);

    impl Drop for DirGuard {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }

    fn open_relative(
        root_fd: RawFd,
        components: &[&str],
        flags: libc::c_int,
    ) -> Result<OwnedFd, CapabilityError> {
        #[cfg(target_os = "linux")]
        {
            match openat2(root_fd, components, flags) {
                Ok(fd) => return Ok(fd),
                Err(error) if is_openat2_unavailable(&error) => {}
                Err(error) => return Err(map_io("fs::open", error)),
            }
        }
        open_component_walk(root_fd, components, flags).map_err(|error| map_io("fs::open", error))
    }

    #[cfg(target_os = "linux")]
    fn is_openat2_unavailable(error: &io::Error) -> bool {
        matches!(
            error.raw_os_error(),
            Some(libc::ENOSYS) | Some(libc::EINVAL) | Some(libc::EOPNOTSUPP)
        )
    }

    #[cfg(target_os = "linux")]
    fn openat2(
        root_fd: RawFd,
        components: &[&str],
        flags: libc::c_int,
    ) -> Result<OwnedFd, io::Error> {
        #[repr(C)]
        struct OpenHow {
            flags: u64,
            mode: u64,
            resolve: u64,
        }
        const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
        const RESOLVE_NO_SYMLINKS: u64 = 0x04;
        const RESOLVE_BENEATH: u64 = 0x08;
        if components.is_empty() {
            return duplicate_fd(root_fd);
        }
        let mut relative = Vec::new();
        for (index, component) in components.iter().enumerate() {
            if index != 0 {
                relative.push(b'/');
            }
            relative.extend_from_slice(component.as_bytes());
        }
        let path = CString::new(relative).expect("validated components contain no NUL");
        let how = OpenHow {
            flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root_fd,
                path.as_ptr(),
                &how,
                std::mem::size_of::<OpenHow>(),
            ) as libc::c_int
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }

    fn open_component_walk(
        root_fd: RawFd,
        components: &[&str],
        flags: libc::c_int,
    ) -> Result<OwnedFd, io::Error> {
        if components.is_empty() {
            return duplicate_fd(root_fd);
        }
        let mut current = duplicate_fd(root_fd)?;
        for component in &components[..components.len() - 1] {
            current = open_directory_component(current.as_raw_fd(), component.as_bytes())?;
        }
        let leaf = CString::new(*components.last().expect("nonempty path")).expect("no NUL");
        let fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                leaf.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ELOOP)
                || is_symlink_at(current.as_raw_fd(), leaf.as_c_str().to_bytes())
            {
                return Err(io::Error::from_raw_os_error(libc::ELOOP));
            }
            return Err(error);
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn open_directory_component(parent_fd: RawFd, component: &[u8]) -> Result<OwnedFd, io::Error> {
        let component = CString::new(component).expect("validated component contains no NUL");
        if is_symlink_at(parent_fd, component.as_c_str().to_bytes()) {
            return Err(io::Error::from_raw_os_error(libc::ELOOP));
        }
        let fd = unsafe {
            libc::openat(
                parent_fd,
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }

    fn is_symlink_at(parent_fd: RawFd, name: &[u8]) -> bool {
        let Ok(name) = CString::new(name) else {
            return false;
        };
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                parent_fd,
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            return false;
        }
        let stat = unsafe { stat.assume_init() };
        (stat.st_mode as libc::mode_t) & libc::S_IFMT == libc::S_IFLNK
    }

    fn duplicate_fd(fd: RawFd) -> Result<OwnedFd, io::Error> {
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(duplicate) });
        }
        Err(io::Error::last_os_error())
    }

    fn fstat(fd: RawFd) -> Result<libc::stat, CapabilityError> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        let result = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
        if result < 0 {
            return Err(map_io("fs::stat", io::Error::last_os_error()));
        }
        Ok(unsafe { stat.assume_init() })
    }

    fn stat_u64(value: impl TryInto<u64>) -> u64 {
        value.try_into().unwrap_or(u64::MAX)
    }

    fn map_io(operation: &str, error: io::Error) -> CapabilityError {
        let code = match error.raw_os_error() {
            Some(libc::ELOOP | libc::EXDEV | libc::ENOTDIR | libc::EPERM | libc::EACCES) => {
                "path_denied"
            }
            Some(libc::ENOENT) => "not_found",
            Some(libc::ESTALE) => "path_denied",
            _ => "path_denied",
        };
        CapabilityError::new(code, format!("{operation}: {error}"))
    }

    #[cfg(test)]
    mod errno_tests {
        use super::*;

        #[test]
        fn readdir_end_never_treats_unknown_errno_abi_as_eof() {
            assert!(classify_readdir_end(ErrnoAbi::Known(0)).is_ok());
            let error = classify_readdir_end(ErrnoAbi::Known(5))
                .expect_err("nonzero errno must not be treated as EOF");
            assert_ne!(error.code(), "unsupported_platform");
            let unsupported = classify_readdir_end(ErrnoAbi::Unsupported)
                .expect_err("missing errno ABI must fail closed");
            assert_eq!(unsupported.code(), "unsupported_platform");
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        #[test]
        fn linux_errno_location_clears_and_reads_zero() {
            clear_errno();
            assert!(matches!(errno_abi(), ErrnoAbi::Known(0)));
        }

        #[cfg(any(
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "ios",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        #[test]
        fn bsd_errno_error_clears_and_reads_zero() {
            clear_errno();
            assert!(matches!(errno_abi(), ErrnoAbi::Known(0)));
        }

        #[test]
        fn current_target_does_not_report_unsupported_when_accessor_exists() {
            match errno_abi() {
                ErrnoAbi::Known(_) => {
                    #[cfg(not(any(
                        target_os = "linux",
                        target_os = "android",
                        target_os = "dragonfly",
                        target_os = "freebsd",
                        target_os = "ios",
                        target_os = "macos",
                        target_os = "netbsd",
                        target_os = "openbsd"
                    )))]
                    panic!("unsupported Unix target must fail closed");
                }
                ErrnoAbi::Unsupported => {
                    #[cfg(any(
                        target_os = "linux",
                        target_os = "android",
                        target_os = "dragonfly",
                        target_os = "freebsd",
                        target_os = "ios",
                        target_os = "macos",
                        target_os = "netbsd",
                        target_os = "openbsd"
                    ))]
                    panic!("supported target must expose a real errno accessor");
                }
            }
        }
    }
}
