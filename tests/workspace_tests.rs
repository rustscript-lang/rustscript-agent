use std::fs;
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct GatewayProcess {
    child: Child,
    reaped: bool,
    stderr_path: PathBuf,
}

impl GatewayProcess {
    fn stop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        self.child.wait().expect("gateway child should be reaped");
        self.reaped = true;
    }

    fn stderr(&self) -> String {
        fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }
}

impl Drop for GatewayProcess {
    fn drop(&mut self) {
        if !self.reaped {
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
            }
            let _ = self.child.wait();
            self.reaped = true;
        }
    }
}

fn assigned_test_root() -> PathBuf {
    let base = PathBuf::from(
        std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMPDIR")
            .expect("RUSTSCRIPT_AGENT_TEST_TMPDIR must point into assigned TEMP"),
    );
    base.join(format!("gateway-workspace-cli-{}", uuid::Uuid::new_v4()))
}

fn private_config(home: &Path, workspace: &Path) {
    fs::create_dir_all(home).expect("create private gateway home");
    fs::create_dir_all(workspace).expect("create configured workspace");
    let config = format!(
        "version: 1\nmodel:\n  provider: local-test\n  model: synthetic\nproviders:\n  local-test:\n    protocol: codex-responses\n    base_url: https://127.0.0.1:1\nworkspaces:\n  allowed_roots:\n    - '{}'\n  default: '{}'\n  named:\n    project: '{}'\n",
        workspace.display(),
        workspace.display(),
        workspace.display()
    );
    fs::write(home.join("config.yaml"), config).expect("write synthetic workspace policy");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("private home mode");
        fs::set_permissions(home.join("config.yaml"), fs::Permissions::from_mode(0o600))
            .expect("private config mode");
    }
}

fn spawn_gateway(
    root: &Path,
    home: &Path,
    workspace_home: Option<&Path>,
) -> (GatewayProcess, SocketAddr) {
    fs::create_dir_all(root).expect("create private process fixture");
    fs::create_dir_all(home).expect("create private HOME");
    let current_dir = root.join("cwd");
    fs::create_dir_all(&current_dir).expect("create non-workspace current directory");
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    let address = listener.local_addr().expect("loopback address");
    drop(listener);
    let stderr_path = root.join("gateway.stderr");
    let stderr = fs::File::create(&stderr_path).expect("create assigned stderr log");
    let assigned_tmp = std::env::var_os("RUSTSCRIPT_AGENT_TEST_TMPDIR")
        .expect("assigned test temporary directory");

    let mut command = Command::new(env!("CARGO_BIN_EXE_rustscript-agent-gateway"));
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("TMPDIR", &assigned_tmp)
        .env("RUSTSCRIPT_AGENT_TEST_TMPDIR", &assigned_tmp)
        .env("RUSTSCRIPT_AGENT_GATEWAY_ADDR", address.to_string())
        .env("RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS", "1")
        .current_dir(current_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr));
    if let Some(workspace_home) = workspace_home {
        command.env("RUSTSCRIPT_AGENT_HOME", workspace_home);
    }
    let child = command.spawn().expect("gateway executable should spawn");
    (
        GatewayProcess {
            child,
            reaped: false,
            stderr_path,
        },
        address,
    )
}

async fn request_json(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: &Value,
) -> io::Result<(u16, Value)> {
    let mut stream = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(address))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "loopback connect timed out"))??;
    let body = body.to_string();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "loopback response timed out"))??;
    let response = String::from_utf8(response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP response lacks headers"))?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP status is invalid"))?;
    let body = serde_json::from_str(body.trim())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok((status, body))
}

async fn wait_for_health(process: &mut GatewayProcess, address: SocketAddr) -> (u16, Value) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = process.child.try_wait().expect("check gateway process") {
            panic!(
                "gateway exited before health became available ({status}): {}",
                process.stderr()
            );
        }
        if let Ok(response) = request_json(address, "GET", "/health/detailed", &Value::Null).await {
            return response;
        }
        assert!(
            Instant::now() < deadline,
            "gateway health did not become available: {}",
            process.stderr()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn gateway_cli_bootstraps_private_workspace_home_without_auth_or_oauth() {
    let root = assigned_test_root();
    let absent_home = root.join("absent-home");
    let (mut absent, absent_address) = spawn_gateway(&root.join("absent-case"), &absent_home, None);
    let (status, health) = wait_for_health(&mut absent, absent_address).await;
    assert_eq!(status, 200, "anonymous health response: {health}");
    assert_eq!(health["status"], "ok");
    let absent_session = "cli-workspace-absent";
    let (status, created) = request_json(
        absent_address,
        "POST",
        "/api/sessions",
        &json!({"id": absent_session, "source": "http", "model": "synthetic", "provider": "local-test"}),
    )
    .await
    .expect("anonymous session creation should respond");
    assert_eq!(status, 201, "anonymous session creation: {created}");
    let (status, rejected) = request_json(
        absent_address,
        "POST",
        &format!("/v1/sessions/{absent_session}/workspace"),
        &json!({"workspace": "name:project"}),
    )
    .await
    .expect("workspace request without RUSTSCRIPT_AGENT_HOME should respond");
    assert_eq!(
        status, 422,
        "workspace bootstrap needs an explicit home: {rejected}"
    );
    assert_eq!(rejected["error"]["code"], "workspace_rejected");
    absent.stop();

    let present_root = root.join("present-case");
    let home = present_root.join("private-home");
    let workspace = present_root.join("allowed-workspace");
    private_config(&home, &workspace);
    let (mut present, present_address) = spawn_gateway(&present_root, &home, Some(&home));
    let (status, health) = wait_for_health(&mut present, present_address).await;
    assert_eq!(
        status, 200,
        "anonymous health response with private home: {health}"
    );
    assert_eq!(health["status"], "ok");
    let present_session = "cli-workspace-present";
    let (status, created) = request_json(
        present_address,
        "POST",
        "/api/sessions",
        &json!({"id": present_session, "source": "http", "model": "synthetic", "provider": "local-test"}),
    )
    .await
    .expect("anonymous session creation with private home should respond");
    assert_eq!(status, 201, "anonymous session creation: {created}");
    let (status, bound) = request_json(
        present_address,
        "POST",
        &format!("/v1/sessions/{present_session}/workspace"),
        &json!({"workspace": "name:project"}),
    )
    .await
    .expect("workspace binding through the gateway process should respond");
    assert_eq!(status, 200, "workspace-only bootstrap: {bound}");
    assert_eq!(bound["session"]["workspace"]["selector"], "name:project");
    assert_eq!(
        bound["session"]["workspace"]["canonical_path"],
        workspace
            .canonicalize()
            .expect("canonical workspace")
            .display()
            .to_string()
    );
    assert!(
        !home.join("auth.json").exists(),
        "workspace bootstrap must not create an OAuth/auth store"
    );
    present.stop();
    fs::remove_dir_all(root).expect("remove assigned process fixtures");
}
