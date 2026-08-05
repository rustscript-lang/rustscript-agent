use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use rustscript_agent::{AgentConfig, AgentRunner};
use rustscript_vm::Value;

fn spawn_fixture() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture");
    let port = listener.local_addr().expect("fixture address").port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fixture request");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).expect("read fixture request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nX-Agent: fixture\r\n\r\nagent-ok")
            .expect("write fixture response");
    });
    (port, handle)
}

#[test]
fn runs_script_owned_http_call_to_completion() {
    let (port, fixture) = spawn_fixture();
    let source = format!(
        r#"
        use http;
        http::client::request({{
            method: "GET",
            url: "http://127.0.0.1:{port}/",
        }});
        "#
    );
    let mut config = AgentConfig::for_hosts(["127.0.0.1"]);
    config.http.allowed_schemes = vec!["http".to_string()];
    config.http.allowed_ports = vec![port];
    config.http.allow_private_ips = true;

    let result = AgentRunner::from_source(&source, config)
        .expect("compile agent")
        .run()
        .expect("run agent");
    fixture.join().expect("fixture thread");

    let Value::Map(response) = result else {
        panic!("expected response map");
    };
    let status = response
        .get(&Value::string("status"))
        .expect("status field");
    assert_eq!(status, &Value::Int(200));
    let body = response.get(&Value::string("body")).expect("body field");
    assert_eq!(body, &Value::bytes(b"agent-ok"));
    let headers = response
        .get(&Value::string("headers"))
        .expect("headers field");
    let Value::Map(headers) = headers else {
        panic!("expected response headers map");
    };
    assert_eq!(
        headers.get(&Value::string("x-agent")),
        Some(&Value::string("fixture"))
    );
}

#[test]
fn default_policy_rejects_http_destination() {
    let runner = AgentRunner::from_source(
        r#"
        use http;
        http::client::request({ method: "GET", url: "http://127.0.0.1:1/" });
        "#,
        AgentConfig::default(),
    )
    .expect("compile agent");
    let error = runner
        .run()
        .expect_err("default policy must reject destination");
    assert!(error.to_string().contains("not allowed"));
}
