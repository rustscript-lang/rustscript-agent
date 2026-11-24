//! Synchronous last-resort cleanup for an owned Tokio fixture subprocess.
use std::io;
use std::ops::{Deref, DerefMut};
use std::process::ExitStatus;
use std::time::Duration;
use tokio::process::{Child, Command};

pub struct OwnedAsyncChild(Child);

impl OwnedAsyncChild {
    pub fn spawn(command: &mut Command) -> io::Result<Self> {
        command.kill_on_drop(true).spawn().map(Self)
    }

    pub fn kill_and_reap(&mut self) -> io::Result<ExitStatus> {
        if self.0.id().is_some()
            && let Err(kill_error) = self.0.start_kill()
        {
            return self.0.try_wait()?.ok_or(kill_error);
        }
        // Child::try_wait performs the actual waitpid without driving Tokio.
        // In Drop we cannot await or rely on the runtime's orphan reaper.
        loop {
            match self.0.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) => std::thread::sleep(Duration::from_millis(1)),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

impl Deref for OwnedAsyncChild {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.0
    }
}

impl DerefMut for OwnedAsyncChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for OwnedAsyncChild {
    fn drop(&mut self) {
        if let Err(error) = self.kill_and_reap() {
            use std::io::Write;
            let _ = writeln!(
                io::stderr(),
                "fixture child reap failed: {:?}",
                error.kind()
            );
        }
    }
}
