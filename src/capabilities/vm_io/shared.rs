//! Pipe and process-group helpers used by the vendored bounded-process backend.

#[cfg(unix)]
pub(super) fn set_pipe_nonblocking(pipe: &impl std::os::fd::AsRawFd) -> std::io::Result<()> {
    let fd = pipe.as_raw_fd();
    // SAFETY: `fd` is borrowed from a live child-pipe object for the duration
    // of each fcntl call; no ownership is transferred.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: same valid borrowed descriptor, with the existing flags retained.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn set_pipe_nonblocking(
    _pipe: &impl std::os::windows::io::AsRawHandle,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Windows child pipes require cancellable I/O rather than PIPE_NOWAIT",
    ))
}

#[cfg(unix)]
pub(crate) fn terminate_process_group(process_id: u32) {
    if let Ok(pid) = libc::pid_t::try_from(process_id) {
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
pub(crate) fn terminate_process_group(process_id: u32) {
    let _ = process_id;
}
