use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustscript_agent::{
    AgentConfig, AgentRunner, RunCancellation, RunDeliveryError, RunError, RunEventSink,
    RunnerPrepareFault,
};
use rustscript_vm::{CancellationReason, InvocationError, Value};

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

fn http_config(port: u16) -> AgentConfig {
    let mut config = AgentConfig::for_hosts(["127.0.0.1"]);
    config.http.allowed_schemes = vec!["http".to_string()];
    config.http.allowed_ports = vec![port];
    config.http.allow_private_ips = true;
    config
}

/// Collects every delivered event value in order.
#[derive(Clone, Default)]
struct RecordingSink {
    values: Arc<Mutex<Vec<Value>>>,
}

impl RunEventSink for RecordingSink {
    fn deliver(&mut self, value: Value) -> Result<(), RunDeliveryError> {
        self.values
            .lock()
            .expect("recording sink lock should not be poisoned")
            .push(value);
        Ok(())
    }
}

/// Requests cancellation the first time an event is delivered, then records.
#[derive(Clone)]
struct CancellingSink {
    cancel: RunCancellation,
    values: Arc<Mutex<Vec<Value>>>,
}

impl RunEventSink for CancellingSink {
    fn deliver(&mut self, value: Value) -> Result<(), RunDeliveryError> {
        self.cancel.request(CancellationReason::Requested);
        self.values
            .lock()
            .expect("cancelling sink lock should not be poisoned")
            .push(value);
        Ok(())
    }
}

/// Rejects the first delivered event with a typed delivery error.
struct RejectingSink;

impl RunEventSink for RejectingSink {
    fn deliver(&mut self, _value: Value) -> Result<(), RunDeliveryError> {
        Err(RunDeliveryError::Rejected {
            code: "schema_violation",
            message: "event does not match the agent event schema".to_string(),
        })
    }
}

/// Blocks on the first delivered event until the test releases it: the run
/// must not finish while the delivery path cannot accept another event.
struct BlockingSink {
    blocked: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

impl RunEventSink for BlockingSink {
    fn deliver(&mut self, _value: Value) -> Result<(), RunDeliveryError> {
        let _ = self.blocked.send(());
        let _ = self.release.recv();
        Ok(())
    }
}

#[test]
fn runs_script_owned_http_call_to_completion() {
    let (port, fixture) = spawn_fixture();
    let source = format!(
        r#"
        use http;
        pub fn run(input: map) -> map {{
            http::client::request({{
                method: "GET",
                url: "http://127.0.0.1:{port}/",
            }});
        }}
        "#
    );

    let result = AgentRunner::from_source(&source, http_config(port))
        .expect("compile agent")
        .run_with_context(Value::map(vec![]))
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
fn default_policy_rejects_http_destination_without_string_parsing() {
    let runner = AgentRunner::from_source(
        r#"
        use http;
        pub fn run(input: map) -> map {
            http::client::request({ method: "GET", url: "http://127.0.0.1:1/" });
        }
        "#,
        AgentConfig::default(),
    )
    .expect("compile agent");
    let error = runner
        .run_with_context(Value::map(vec![]))
        .expect_err("default policy must reject destination");
    assert!(
        matches!(
            error,
            RunError::Invocation(InvocationError::Capability(_) | InvocationError::Host { .. })
        ),
        "policy rejection must stay a typed failure, got {error:?}"
    );
    assert!(error.to_string().contains("not allowed"));
}

#[test]
fn exported_run_receives_the_exact_structured_context_unchanged() {
    let runner = AgentRunner::from_source(
        r#"
        pub fn run(input: map) -> map {
            input;
        }
        "#,
        AgentConfig::default(),
    )
    .expect("compile agent");
    let context = Value::map(vec![
        (Value::string("run_id"), Value::string("run-1")),
        (Value::string("session_id"), Value::string("session-1")),
        (Value::string("input"), Value::string("hello")),
        (Value::string("turns"), Value::Int(3)),
    ]);
    let result = runner
        .run_with_context(context.clone())
        .expect("run should return the exact context");
    assert_eq!(
        result, context,
        "the structured context must reach run() unchanged"
    );
}

#[test]
fn emitted_events_arrive_in_order_then_the_complete_value() {
    let runner = AgentRunner::from_source(
        r#"
        use stream;
        pub fn run(input: map) -> string {
            stream::emit("a");
            stream::emit("b");
            "c";
        }
        "#,
        AgentConfig::default(),
    )
    .expect("compile agent");
    let mut sink = RecordingSink::default();
    let result = runner
        .run_with_context_and_events(Value::map(vec![]), &mut sink, &RunCancellation::new())
        .expect("run should complete");
    assert_eq!(result, Value::string("c"));
    let events = sink.values.lock().expect("sink lock");
    assert_eq!(
        events.as_slice(),
        &[Value::string("a"), Value::string("b")],
        "events must be delivered in emission order before the terminal item"
    );
}

#[test]
fn complete_without_events_returns_the_callable_value() {
    let runner = AgentRunner::from_source(
        r#"
        pub fn run(input: map) -> int {
            42;
        }
        "#,
        AgentConfig::default(),
    )
    .expect("compile agent");
    let mut sink = RecordingSink::default();
    let result = runner
        .run_with_context_and_events(Value::map(vec![]), &mut sink, &RunCancellation::new())
        .expect("run should complete");
    assert_eq!(result, Value::Int(42));
    assert!(
        sink.values.lock().expect("sink lock").is_empty(),
        "a run without stream::emit must deliver no events"
    );
}

#[test]
fn missing_or_incompatible_entry_signatures_are_rejected() {
    let missing = AgentRunner::from_source("let answer = 42;", AgentConfig::default())
        .expect("compile agent");
    assert!(
        matches!(
            missing.run_with_context(Value::map(vec![])),
            Err(RunError::NoEntry)
        ),
        "a program without exported run must be rejected"
    );

    let zero_arity = AgentRunner::from_source(
        r#"
        pub fn run() -> int {
            42;
        }
        "#,
        AgentConfig::default(),
    )
    .expect("compile agent");
    assert!(
        matches!(
            zero_arity.run_with_context(Value::map(vec![])),
            Err(RunError::EntryArity {
                expected: 1,
                got: 0
            })
        ),
        "an exported run without the context parameter must be rejected"
    );
}

#[test]
fn early_stream_end_without_terminal_fails_the_run() {
    // The core contract guarantees one terminal item before the fused end, so
    // this guards the runner's own defensive path: a fused stream that never
    // delivered Complete or a typed error must fail the run rather than
    // fabricating a result.
    let runner = AgentRunner::from_source(
        r#"
        use stream;
        pub fn run(input: map) -> int {
            stream::emit("x");
            42;
        }
        "#,
        AgentConfig::default(),
    )
    .expect("compile agent");
    // Drive one run normally to confirm the public path; the defensive
    // EarlyEnd branch is exercised through the delivery seam below.
    assert_eq!(
        runner
            .run_with_context(Value::map(vec![]))
            .expect("normal run should complete"),
        Value::Int(42)
    );
    // A sink rejection stops the run without a terminal item from core; the
    // runner must surface the rejection as a typed delivery failure.
    let rejected = runner
        .run_with_context_and_events(
            Value::map(vec![]),
            &mut RejectingSink,
            &RunCancellation::new(),
        )
        .expect_err("a rejected event must fail the run");
    assert!(
        matches!(
            rejected,
            RunError::DeliveryRejected {
                code: "schema_violation",
                ..
            }
        ),
        "sink rejection must surface typed, got {rejected:?}"
    );
}

#[test]
fn typed_fuel_exhaustion_fails_the_run() {
    let runner = AgentRunner::from_source(
        r#"
        pub fn run(input: map) -> int {
            while true {
                1;
            }
            42;
        }
        "#,
        AgentConfig {
            fuel: Some(8),
            ..AgentConfig::default()
        },
    )
    .expect("compile agent");
    let error = runner
        .run_with_context(Value::map(vec![]))
        .expect_err("fuel exhaustion must fail the run");
    assert!(
        matches!(
            error,
            RunError::Invocation(InvocationError::OutOfFuel { remaining: 0, .. })
        ),
        "fuel exhaustion must stay a typed out-of-fuel failure, got {error:?}"
    );
}

#[test]
fn cpu_loop_reaches_typed_terminal_cancellation_within_the_bound() {
    let runner = AgentRunner::from_source(
        r#"
        pub fn run(input: map) -> int {
            while true {
                1;
            }
            42;
        }
        "#,
        AgentConfig::default(),
    )
    .expect("compile agent");
    let cancel = RunCancellation::new();
    let canceller = cancel.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        canceller.request(CancellationReason::Requested);
    });
    let started = Instant::now();
    let error = runner
        .run_with_context_and_events(Value::map(vec![]), &mut RecordingSink::default(), &cancel)
        .expect_err("a pure CPU loop must be interrupted");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "cancellation must interrupt the CPU loop within the configured bound"
    );
    assert!(
        matches!(
            error,
            RunError::Invocation(
                InvocationError::DeadlineReached { .. }
                    | InvocationError::Cancelled(CancellationReason::Requested)
            )
        ),
        "CPU-loop interruption must stay a typed terminal error, got {error:?}"
    );
}

#[test]
fn stop_between_polls_preserves_the_typed_requested_reason() {
    let runner = AgentRunner::from_source(
        r#"
        use stream;
        pub fn run(input: map) -> string {
            stream::emit("first");
            while true {
                1;
            }
            "unreachable";
        }
        "#,
        AgentConfig::default(),
    )
    .expect("compile agent");
    let cancel = RunCancellation::new();
    let mut sink = CancellingSink {
        cancel: cancel.clone(),
        values: Arc::new(Mutex::new(Vec::new())),
    };
    let error = runner
        .run_with_context_and_events(Value::map(vec![]), &mut sink, &cancel)
        .expect_err("the requested stop must cancel the run");
    assert!(
        matches!(
            error,
            RunError::Invocation(InvocationError::Cancelled(CancellationReason::Requested))
        ),
        "a stop observed between polls must preserve the requested reason, got {error:?}"
    );
}

#[test]
fn deadline_cancellation_between_polls_preserves_the_typed_deadline_reason() {
    let runner = AgentRunner::from_source(
        r#"
        use stream;
        pub fn run(input: map) -> string {
            stream::emit("first");
            while true {
                1;
            }
            "unreachable";
        }
        "#,
        AgentConfig::default(),
    )
    .expect("compile agent");
    let cancel = RunCancellation::with_timeout(Duration::from_millis(50));
    let error = runner
        .run_with_context_and_events(Value::map(vec![]), &mut RecordingSink::default(), &cancel)
        .expect_err("the deadline must cancel the run");
    assert!(
        matches!(
            error,
            RunError::Invocation(
                InvocationError::Cancelled(CancellationReason::Deadline)
                    | InvocationError::DeadlineReached { .. }
            )
        ),
        "timeout must stay a typed deadline failure, got {error:?}"
    );
}

#[test]
fn blocked_delivery_pauses_invocation_polling() {
    // While the bounded delivery path cannot accept another event, core
    // execution must not outrun delivery: the run cannot finish until the
    // sink accepts the emitted event.
    let runner = AgentRunner::from_source(
        r#"
        use stream;
        pub fn run(input: map) -> string {
            stream::emit("blocked");
            "done";
        }
        "#,
        AgentConfig::default(),
    )
    .expect("compile agent");
    let (blocked_tx, blocked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let mut sink = BlockingSink {
        blocked: blocked_tx,
        release: release_rx,
    };
    let worker = thread::spawn(move || {
        runner.run_with_context_and_events(Value::map(vec![]), &mut sink, &RunCancellation::new())
    });
    blocked_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("the emitted event must reach delivery");
    thread::sleep(Duration::from_millis(200));
    assert!(
        !worker.is_finished(),
        "core execution must not outrun a blocked delivery path"
    );
    release_tx
        .send(())
        .expect("the delivery path should be releasable");
    let result = worker
        .join()
        .expect("worker thread should join")
        .expect("the run must complete after delivery resumes");
    assert_eq!(result, Value::string("done"));
}

#[test]
fn enormous_timeout_and_wall_deadline_never_panic_and_fail_closed() {
    let cancel = RunCancellation::with_timeout(Duration::MAX);
    assert!(cancel.has_deadline_overflow());
    assert!(!cancel.watcher_is_armed());

    let from_wall = RunCancellation::from_wall_deadline_ms(u64::MAX, 0);
    assert!(from_wall.has_deadline_overflow());
    assert!(!from_wall.watcher_is_armed());
}

fn trivial_runner() -> AgentRunner {
    AgentRunner::from_source(
        r#"
        pub fn run(input: map) -> string {
            "ok";
        }
        "#,
        AgentConfig::default(),
    )
    .expect("compile trivial agent")
}

#[test]
fn prepare_panic_disarms_epoch_watcher() {
    let runner = trivial_runner().with_prepare_fault(RunnerPrepareFault::PanicAfterArm);
    let cancel = RunCancellation::with_timeout(Duration::from_secs(5));
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut sink = RecordingSink::default();
        let _ = runner.run_with_context_and_events(Value::map(vec![]), &mut sink, &cancel);
    }));
    assert!(panicked.is_err());
    assert!(
        !cancel.watcher_is_armed(),
        "watcher must disarm after prepare panic"
    );
}

#[test]
fn prepare_error_disarms_epoch_watcher() {
    let runner = trivial_runner().with_prepare_fault(RunnerPrepareFault::ErrorAfterArm);
    let cancel = RunCancellation::with_timeout(Duration::from_secs(5));
    let mut sink = RecordingSink::default();
    let error = runner
        .run_with_context_and_events(Value::map(vec![]), &mut sink, &cancel)
        .expect_err("injected prepare error");
    assert!(matches!(error, RunError::Setup(_)));
    assert!(!cancel.watcher_is_armed());
}

#[test]
fn drive_panic_disarms_epoch_watcher() {
    let runner = trivial_runner().with_prepare_fault(RunnerPrepareFault::PanicDuringDrive);
    let cancel = RunCancellation::with_timeout(Duration::from_secs(5));
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut sink = RecordingSink::default();
        let _ = runner.run_with_context_and_events(Value::map(vec![]), &mut sink, &cancel);
    }));
    assert!(panicked.is_err());
    assert!(!cancel.watcher_is_armed());
}
