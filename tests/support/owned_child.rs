//! Fallible output capture without relinquishing ownership of a fixture child.
use std::io::{self, Read};
use std::ops::{Deref, DerefMut};
use std::process::{Child, Command, Output, Stdio};

pub struct OwnedChild {
    child: Child,
    #[cfg(target_os = "linux")]
    group: bool,
}

impl OwnedChild {
    pub fn spawn(command: &mut Command) -> io::Result<Self> {
        Ok(Self {
            child: command.spawn()?,
            #[cfg(target_os = "linux")]
            group: false,
        })
    }

    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    pub fn spawn_in_own_group(command: &mut Command) -> io::Result<Self> {
        use std::os::unix::process::CommandExt;
        let mut owned = Self::spawn(command.process_group(0))?;
        owned.group = true;
        Ok(owned)
    }

    pub fn output(command: &mut Command) -> io::Result<Output> {
        Self::spawn(
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )?
        .wait_with_output()
    }

    pub fn wait_with_output(mut self) -> io::Result<Output> {
        drop(self.child.stdin.take());
        let stdout = self.child.stdout.take();
        let stderr = self.child.stderr.take();
        std::thread::scope(|scope| {
            let stdout = std::thread::Builder::new().spawn_scoped(scope, || drain(stdout))?;
            let stderr = match std::thread::Builder::new().spawn_scoped(scope, || drain(stderr)) {
                Ok(reader) => reader,
                Err(err) => {
                    self.terminate();
                    return Err(err);
                }
            };
            let status = match self.child.wait() {
                Ok(status) => status,
                Err(err) => {
                    self.terminate();
                    return Err(err);
                }
            };
            Ok(Output {
                status,
                stdout: stdout
                    .join()
                    .map_err(|_| io::Error::other("stdout reader panicked"))??,
                stderr: stderr
                    .join()
                    .map_err(|_| io::Error::other("stderr reader panicked"))??,
            })
        })
    }

    fn terminate(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            #[cfg(target_os = "linux")]
            if self.group {
                // The process group was created atomically by this spawn and its leader is unreaped.
                unsafe { libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL) };
            }
            let _ = self.child.kill();
        }
        if let Err(error) = self.child.wait() {
            use std::io::Write;
            let _ = writeln!(
                io::stderr(),
                "fixture child reap failed: {:?}",
                error.kind()
            );
        }
    }
}

impl Deref for OwnedChild {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.child
    }
}

impl DerefMut for OwnedChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn drain(pipe: Option<impl Read>) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    if let Some(mut pipe) = pipe {
        pipe.read_to_end(&mut output)?;
    }
    Ok(output)
}
