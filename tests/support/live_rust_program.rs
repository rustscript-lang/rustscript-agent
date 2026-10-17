use super::*;
#[path = "live_http_delivery.rs"]
mod live_http_delivery;

const FAKE_REFRESH: &str = "SYNTHETIC_INVALID_REFRESH_FOR_ACCESS_ONLY_TEST";
#[derive(Default)]
struct MultiTurnCounts {
    allowed: AtomicUsize,
    blocked: AtomicUsize,
    refresh_attempts: AtomicUsize,
    business: AtomicUsize,
    guardian: AtomicUsize,
    observations: std::sync::Mutex<Vec<Value>>,
}

struct ObservedLiveStream {
    received: usize,
    pending_line: Vec<u8>,
    last_kind: String,
    completed_seen: bool,
    inner: Box<dyn BoundedHttpsStream>,
    counts: Arc<MultiTurnCounts>,
}
impl BoundedHttpsStream for ObservedLiveStream {
    fn head(&self) -> &rustscript_agent::auth::oauth::RawHttpsResponseHead {
        self.inner.head()
    }
    fn read_chunk(&mut self) -> Result<Option<Vec<u8>>, OAuthError> {
        let result = self.inner.read_chunk();
        if let Ok(Some(chunk)) = &result {
            self.received += chunk.len();
            for byte in chunk {
                if *byte == b'\n' {
                    if let Some(data) = self.pending_line.strip_prefix(b"data: ")
                        && let Ok(value) = serde_json::from_slice::<Value>(data)
                    {
                        let kind = value
                            .get("type")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        self.last_kind = match kind {
                            "response.completed" => {
                                self.completed_seen = true;
                                "completed"
                            }
                            "response.output_item.done" => "item_done",
                            "response.output_text.delta" => "text_delta",
                            "response.function_call_arguments.delta" => "args_delta",
                            "response.metadata" => "metadata",
                            "error" => "error",
                            _ => "other",
                        }
                        .into();
                    }
                    self.pending_line.clear();
                } else if self.pending_line.len() < 65536 {
                    self.pending_line.push(*byte);
                }
            }
        }
        if let Err(error) = &result {
            let detail = match error {
                OAuthError::Transport { message }
                    if matches!(
                        message.as_str(),
                        "native_https_failed"
                            | "native_https_incomplete_body"
                            | "native_https_body_parse_failed"
                            | "native_https_body_closed"
                            | "native_https_body_failed"
                            | "native_https_body_io_eof"
                            | "native_https_body_io_reset"
                            | "native_https_body_io_invalid_data"
                            | "native_https_body_io_invalid_input"
                            | "native_https_body_io_other"
                            | "native_https_chunk_extensions_limit"
                            | "native_https_chunk_trailers_invalid"
                            | "native_https_chunk_framing_invalid"
                            | "native_https_tls_close_notify_missing"
                    ) =>
                {
                    message.as_str()
                }
                _ => "withheld",
            };
            self.counts.observations.lock().unwrap().push(json!({"phase":"read","code":error.code(),"detail":detail,"bytes":self.received,"completed_seen":self.completed_seen,"last_kind":self.last_kind}));
        }
        result
    }
    fn cancel(&mut self) {
        self.inner.cancel();
    }
}

struct MultiTurnResponsesTransport {
    inner: NativeHttpsTransport,
    counts: Arc<MultiTurnCounts>,
}

impl MultiTurnResponsesTransport {
    fn new(counts: Arc<MultiTurnCounts>) -> Self {
        Self {
            inner: NativeHttpsTransport::new(),
            counts,
        }
    }

    fn admit(&self, request: &PreparedHttpsRequest) -> Result<(), OAuthError> {
        if request.url.ends_with("/oauth/token") {
            self.counts.refresh_attempts.fetch_add(1, Ordering::SeqCst);
        }
        if request.method != "POST" || request.url != RESPONSE_URL {
            self.counts.blocked.fetch_add(1, Ordering::SeqCst);
            return Err(OAuthError::Transport {
                message: "real rust program E2E blocked non-Responses request".into(),
            });
        }
        let wire = serde_json::from_str::<Value>(&request.body).ok();
        let model_ok = wire
            .as_ref()
            .is_some_and(|wire| wire["model"] == "gpt-6.1-sol");
        let stream_ok = wire.as_ref().is_some_and(|wire| wire["stream"] == true);
        let store_ok = wire.as_ref().is_some_and(|wire| wire["store"] == false);
        let instructions_ok = wire.as_ref().is_some_and(|wire| {
            wire["instructions"]
                .as_str()
                .is_some_and(|instructions| !instructions.is_empty())
        });
        let input_ok = wire
            .as_ref()
            .and_then(|wire| wire.get("input"))
            .and_then(Value::as_array)
            .is_some_and(|input| !input.is_empty());
        let tools_opt = wire.as_ref().and_then(|wire| wire.get("tools"));
        let (tools_ok, is_guardian) = match tools_opt {
            None | Some(Value::Null) => (true, true),
            Some(Value::Array(items)) if items.is_empty() => (true, true),
            Some(Value::Array(items)) => {
                let mut ok = true;
                for tool in items {
                    let type_ok = tool["type"] == "function";
                    let name_ok = matches!(
                        tool["name"].as_str(),
                        Some("read_file")
                            | Some("search_files")
                            | Some("write_file")
                            | Some("patch")
                            | Some("terminal")
                            | Some("process")
                    );
                    let params_ok = tool.get("parameters").is_some_and(Value::is_object);
                    if !(type_ok && name_ok && params_ok) {
                        ok = false;
                        break;
                    }
                }
                (ok, false)
            }
            _ => (false, false),
        };
        if !(model_ok && stream_ok && store_ok && instructions_ok && input_ok && tools_ok) {
            return Err(OAuthError::InvalidIntent {
                reason: "real rust program E2E request body failed validation".into(),
            });
        }
        self.counts.allowed.fetch_add(1, Ordering::SeqCst);
        if is_guardian {
            self.counts.guardian.fetch_add(1, Ordering::SeqCst);
        } else {
            self.counts.business.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
}

impl BoundedHttpsTransport for MultiTurnResponsesTransport {
    fn send(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        self.admit(request)?;
        self.inner.send(request, context)
    }

    fn start_stream(
        &self,
        request: &PreparedHttpsRequest,
        context: &OAuthIoContext,
    ) -> Result<Box<dyn BoundedHttpsStream>, OAuthError> {
        self.admit(request)?;
        match self.inner.start_stream(request, context) {
            Ok(inner) => {
                self.counts
                    .observations
                    .lock()
                    .unwrap()
                    .push(json!({"phase":"head","status":inner.head().status}));
                Ok(Box::new(ObservedLiveStream {
                    received: 0,
                    pending_line: vec![],
                    last_kind: String::new(),
                    completed_seen: false,
                    inner,
                    counts: Arc::clone(&self.counts),
                }))
            }
            Err(error) => {
                self.counts
                    .observations
                    .lock()
                    .unwrap()
                    .push(json!({"phase":"start","code":error.code()}));
                Err(error)
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "manual: real multi-turn Rust program via Native cached access-only authorization"]
async fn real_rust_program_multi_turn_tool_e2e() {
    run_real_rust_program_e2e(false, false).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "manual: real cached access plus fake refresh and live HTTP SSE delivery"]
async fn real_rust_program_fake_refresh_live_delivery_e2e() {
    run_real_rust_program_e2e(true, false).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "manual: full API Server HTTP admission through real tools and final delivery"]
async fn real_api_server_http_rust_program_e2e() {
    run_real_rust_program_e2e(true, true).await;
}

async fn run_real_rust_program_e2e(fake_refresh_and_delivery: bool, http_admission: bool) {
    assert_eq!(
        std::env::var(ALLOW_LIVE_ENV).as_deref(),
        Ok("1"),
        "explicit live authorization guard is required"
    );
    let e_root = PathBuf::from(
        std::env::var_os("RUSTSCRIPT_AGENT_LIVE_EVIDENCE_ROOT")
            .expect("caller-assigned live evidence root"),
    );
    assert!(e_root.is_absolute() && e_root.is_dir());
    let project_path = e_root.join("project");
    fs::create_dir(&project_path).expect("fresh empty project");
    let evidence_path = e_root.join("evidence");
    let prompt_path = e_root.join("prompt.txt");
    fs::write(
        &prompt_path,
        include_str!("../fixtures/live_rust_program_prompt.txt"),
    )
    .expect("fixed task prompt");
    let project_str = project_path.to_str().unwrap();
    let evidence_str = evidence_path.to_str().unwrap();
    let prompt_path_str = prompt_path.to_str().unwrap();

    let prompt_text = fs::read_to_string(prompt_path_str).expect("fixed parent prompt text");
    assert!(!prompt_text.is_empty(), "parent prompt must be nonempty");

    let project = PathBuf::from(project_str);
    assert!(project.is_dir(), "E/project must exist");
    let pre_entries: Vec<_> = fs::read_dir(&project)
        .expect("project listing")
        .collect::<Result<_, _>>()
        .expect("project entries");
    assert!(
        pre_entries.is_empty(),
        "E/project must be empty before the real agent runs"
    );

    let (mut access_token, mut source_before) = authorized_access_and_source_snapshot();
    let expires_at_ms = actual_expiry_ms(&access_token);
    let artifacts = LiveArtifacts::create();
    let home = PrivateLiveHome::create(
        artifacts.home(),
        &project,
        std::mem::take(&mut access_token),
        expires_at_ms,
    );
    access_token.zeroize();
    let mut private_auth_before = Vec::new();
    if fake_refresh_and_delivery {
        let path = home.path.join("auth.yaml");
        let mut raw = fs::read(&path).expect("own private test credential");
        let mut document: serde_yaml::Value =
            serde_yaml::from_slice(&raw).expect("own test auth YAML");
        raw.zeroize();
        assert!(document["credentials"][CREDENTIAL_ID]["refresh_token"].is_null());
        document["credentials"][CREDENTIAL_ID]["refresh_token"] =
            serde_yaml::Value::String(FAKE_REFRESH.into());
        let mut bytes = serde_yaml::to_string(&document)
            .expect("fake refresh test YAML")
            .into_bytes();
        fs::write(&path, &bytes).expect("write only the isolated credential file");
        bytes.zeroize();
        let mut readback = fs::read(&path).expect("private credential readback");
        let readback_document: serde_yaml::Value = serde_yaml::from_slice(&readback).unwrap();
        assert_eq!(
            readback_document["credentials"][CREDENTIAL_ID]["refresh_token"].as_str(),
            Some(FAKE_REFRESH)
        );
        private_auth_before = std::mem::take(&mut readback);
    }

    let counts = Arc::new(MultiTurnCounts::default());
    let home_path = home.path.clone();
    let request_counts = Arc::clone(&counts);
    let auth_factory: Arc<dyn Fn(RunCancellation) -> Result<AuthHost, String> + Send + Sync> =
        Arc::new(move |cancellation| {
            let transport: Arc<dyn BoundedHttpsTransport> = Arc::new(
                MultiTurnResponsesTransport::new(Arc::clone(&request_counts)),
            );
            let oauth = Arc::new(OAuthHost::new(
                transport,
                Arc::new(ScriptedCallback::new()),
                Arc::new(ScriptedBrowser::new()),
                Arc::new(SystemOAuthClock),
                Arc::new(RunOAuthCancel::new(cancellation.clone())),
            ));
            AuthHost::new(home_path.clone(), cancellation).map(|host| host.with_oauth_host(oauth))
        });

    let state = AgentGatewayState::with_agent_file_and_sqlite(
        AgentGatewayConfig {
            provider: Some(PROVIDER.into()),
            model: "gpt-6.1-sol".into(),
            bearer_token: fake_refresh_and_delivery
                .then(|| live_http_delivery::LOCAL_BEARER.into()),
            run_timeout: Duration::from_secs(600),
            ..AgentGatewayConfig::default()
        },
        rustscript_agent::bundled_agent_main_path(),
        artifacts.database(),
    )
    .expect("bundled Main with production SQLite driver");
    let service = state.service().clone();
    service
        .set_run_limits(RunLimits::new(64, 128, 1024 * 1024, &project).expect("real task limits"))
        .expect("install real task limits");
    service
        .set_tool_registry(
            rustscript_agent::bundled_tool_registry().expect("canonical RSS registry"),
        )
        .expect("install canonical tool registry");
    if http_admission {
        service.set_workspace_host_factory(Arc::clone(&auth_factory));
    }
    service.set_auth_host_factory(auth_factory);
    service.upsert_provider_profile(
        ProviderProfile::new(
            PROVIDER,
            json!({
                "profile": PROVIDER,
                "protocol": "codex-responses",
                "base_url": "https://chatgpt.com/backend-api/codex",
                "credential_id": CREDENTIAL_ID
            }),
        )
        .expect("public Codex Responses profile"),
    );

    let (run_id, session_id, delivery_observer) = if http_admission {
        let (observer, run_id, session_id) = live_http_delivery::Observer::admit_http(
            state.clone(),
            &prompt_text,
            PROVIDER,
            "gpt-6.1-sol",
            project_str,
        )
        .await;
        (run_id, session_id, Some(observer))
    } else {
        let admitted = service
            .admit(AdmitRunRequest {
                input: Value::String(prompt_text.clone()),
                model: Some("gpt-6.1-sol".into()),
                provider: Some(PROVIDER.into()),
                platform: "real-rust-program-toolchain-e2e".into(),
                ..AdmitRunRequest::default()
            })
            .await
            .expect("real task admission");
        let observer = if fake_refresh_and_delivery {
            Some(live_http_delivery::Observer::start(state.clone(), &admitted.run_id).await)
        } else {
            None
        };
        service
            .clone()
            .run_worker(admitted.run_id.clone(), "ignored".into())
            .await;
        (admitted.run_id, admitted.session_id, observer)
    };
    let delivery_receipt = if let Some(observer) = delivery_observer {
        Some(observer.finish().await)
    } else {
        None
    };

    let events = service.run_events(&run_id);
    let messages = service.session_messages(&session_id);
    let model_calls = service.metrics().snapshot().model_calls;
    let allowed = counts.allowed.load(Ordering::SeqCst);
    let blocked = counts.blocked.load(Ordering::SeqCst);
    let business = counts.business.load(Ordering::SeqCst);
    let guardian = counts.guardian.load(Ordering::SeqCst);

    let requested = event_count(&events, "model.requested");
    let completed = event_count(&events, "model.completed");
    let tool_requested = event_count(&events, "tool.requested");
    let tool_started = event_count(&events, "tool.started");
    let tool_output = event_count(&events, "tool.output");
    let tool_completed = event_count(&events, "tool.completed");
    let tool_failed = event_count(&events, "tool.failed");
    let approval_required = event_count(&events, "approval.required");
    let approval_resolved = event_count(&events, "approval.resolved");
    let run_completed = event_count(&events, "run.completed");
    let run_failed = event_count(&events, "run.failed");
    let error_codes: Vec<String> = events
        .iter()
        .filter_map(|event| event.pointer("/data/error_code").and_then(Value::as_str))
        .map(str::to_owned)
        .collect();
    let error_statuses: Vec<i64> = events
        .iter()
        .filter_map(|event| event.pointer("/data/status").and_then(Value::as_i64))
        .collect();

    let mut tool_sequence: Vec<String> = Vec::new();
    for event in &events {
        if event.get("event").and_then(Value::as_str) == Some("tool.requested")
            && let Some(name) = event.pointer("/data/name").and_then(Value::as_str)
        {
            tool_sequence.push(name.to_string());
        }
    }
    let saw_write_or_patch = tool_sequence
        .iter()
        .any(|name| name == "write_file" || name == "patch");
    let saw_read = tool_sequence.iter().any(|name| name == "read_file");
    let saw_terminal = tool_sequence.iter().any(|name| name == "terminal");

    let blocks: Vec<_> = messages
        .iter()
        .flat_map(|m| rustscript_agent::decode_message_blocks(&m["content"]))
        .collect();
    let terminal_ids: std::collections::HashSet<_> = blocks
        .iter()
        .filter(|b| b.block_type == "tool_call" && b.name.as_deref() == Some("terminal"))
        .filter_map(|b| b.tool_call_id.clone())
        .collect();
    let saw_rustc_arg = blocks
        .iter()
        .filter(|b| b.name.as_deref() == Some("terminal"))
        .filter_map(|b| b.arguments_json.as_deref())
        .filter_map(|args| serde_json::from_str::<Value>(args).ok())
        .any(|args| {
            args["argv"].as_array().is_some_and(|argv| {
                argv.iter()
                    .filter_map(Value::as_str)
                    .any(|arg| arg.ends_with("/rustc") || arg == "rustc")
            })
        });
    let terminal_results: Vec<_> = blocks
        .iter()
        .filter(|b| {
            b.block_type == "tool_result"
                && b.tool_call_id
                    .as_ref()
                    .is_some_and(|id| terminal_ids.contains(id))
        })
        .filter_map(|b| b.result.as_ref()?.get("exit_code")?.as_i64())
        .collect();

    let main_path = project.join("main.rs");
    let sum_tests_path = project.join("sum_tests");
    let sum_cli_path = project.join("sum_cli");
    let main_exists = main_path.is_file();
    let main_content = if main_exists {
        fs::read_to_string(&main_path).ok()
    } else {
        None
    };
    let test_attr_count = main_content
        .as_ref()
        .map(|content| content.matches("#[test]").count())
        .unwrap_or(0);
    let has_fn_main = main_content
        .as_ref()
        .is_some_and(|content| content.contains("fn main"));
    let sum_tests_exists = sum_tests_path.is_file();
    let sum_cli_exists = sum_cli_path.is_file();

    let cli_4_ok = if sum_cli_exists {
        std::process::Command::new(&sum_cli_path)
            .args(["2", "3", "-1"])
            .output()
            .ok()
            .is_some_and(|output| {
                output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "4"
            })
    } else {
        false
    };
    let cli_0_ok = if sum_cli_exists {
        std::process::Command::new(&sum_cli_path)
            .output()
            .ok()
            .is_some_and(|output| {
                output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "0"
            })
    } else {
        false
    };
    let cli_oops_nonzero = if sum_cli_exists {
        std::process::Command::new(&sum_cli_path)
            .arg("oops")
            .output()
            .ok()
            .is_some_and(|output| !output.status.success())
    } else {
        false
    };
    let sum_tests_ok = if sum_tests_exists {
        std::process::Command::new(&sum_tests_path)
            .output()
            .ok()
            .is_some_and(|output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("test result: ok")
            })
    } else {
        false
    };

    let assistant_texts: Vec<String> = messages
        .iter()
        .filter(|message| {
            message.get("session_id").and_then(Value::as_str) == Some(session_id.as_str())
                && message.get("run_id").and_then(Value::as_str) == Some(run_id.as_str())
                && message.get("role").and_then(Value::as_str) == Some("assistant")
        })
        .flat_map(|message| rustscript_agent::decode_message_blocks(&message["content"]))
        .filter_map(|block| block.text)
        .filter(|text| !text.trim().is_empty())
        .collect();
    let completed_output = events
        .iter()
        .find(|event| event["event"] == "run.completed")
        .and_then(|event| event.pointer("/data/output/text"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let last_tool_ordinal = messages
        .iter()
        .filter(|m| m.get("tool_call_id").and_then(Value::as_str).is_some())
        .filter_map(|m| m.get("ordinal").and_then(Value::as_i64))
        .max()
        .unwrap_or(0);
    let final_present = !completed_output.trim().is_empty()
        && messages.iter().any(|m| {
            m["role"] == "assistant"
                && m["finish_reason"] == "stop"
                && m.get("ordinal").and_then(Value::as_i64).unwrap_or(0) > last_tool_ordinal
                && rustscript_agent::decode_message_blocks(&m["content"])
                    .iter()
                    .any(|b| b.text.as_deref() == Some(completed_output))
        });
    let final_len = assistant_texts.iter().map(|text| text.len()).sum::<usize>();
    let final_head = assistant_texts
        .last()
        .map(|text| text.chars().take(2000).collect::<String>())
        .unwrap_or_default();

    fs::create_dir_all(evidence_str).expect("evidence dir");
    fs::write(
        PathBuf::from(evidence_str).join("safe-events.json"),
        serde_json::to_string_pretty(&events).expect("events JSON"),
    )
    .expect("write safe events");
    fs::write(
        PathBuf::from(evidence_str).join("safe-messages.json"),
        serde_json::to_string_pretty(&messages).expect("messages JSON"),
    )
    .expect("write safe messages");

    let refresh_attempts = counts.refresh_attempts.load(Ordering::SeqCst);
    let private_auth_unchanged = if fake_refresh_and_delivery {
        let mut after = fs::read(home.path.join("auth.yaml")).expect("test auth after run");
        let same = after == private_auth_before;
        after.zeroize();
        same
    } else {
        true
    };
    private_auth_before.zeroize();
    let mut source_after = read_source_auth_readonly();
    let source_auth_unchanged = source_after == source_before;
    source_after.zeroize();
    let public_evidence =
        serde_json::to_string(&json!({"events": events,"messages":messages})).unwrap();
    assert!(
        !public_evidence.contains(FAKE_REFRESH),
        "refresh marker must not enter public context"
    );
    let mut delivery_report = json!({"observed":false});
    if let Some(receipt) = &delivery_receipt {
        fs::write(
            PathBuf::from(evidence_str).join("actual-http-delivery.sse"),
            &receipt.wire,
        )
        .unwrap();
        fs::write(
            PathBuf::from(evidence_str).join("delivered-events.json"),
            serde_json::to_vec_pretty(&receipt.events).unwrap(),
        )
        .unwrap();
        fs::write(
            PathBuf::from(evidence_str).join("actual-http-requests.json"),
            serde_json::to_vec_pretty(&receipt.http_trace).unwrap(),
        )
        .unwrap();
        if http_admission {
            let queried_messages = &receipt.http_trace.last().unwrap()["response"]["data"];
            assert_eq!(
                queried_messages,
                &serde_json::to_value(&messages).unwrap(),
                "HTTP messages must match durable SDK messages"
            );
        }
        let delivered_final = receipt
            .events
            .iter()
            .filter(|event| event["event"] == "run.completed")
            .collect::<Vec<_>>();
        let final_matches = delivered_final.len() == 1
            && delivered_final[0]
                .pointer("/output/text")
                .and_then(Value::as_str)
                == Some(completed_output);
        let ordered = receipt
            .events
            .windows(2)
            .all(|pair| pair[0]["seq"].as_u64().unwrap() < pair[1]["seq"].as_u64().unwrap());
        delivery_report = json!({"observed":true,"transport":"actual loopback HTTP SSE","event_count":receipt.events.len(),"terminal_count":delivered_final.len(),"final_text_matches_persisted_business_reply":final_matches,"ordered":ordered,"listener_closed":receipt.listener_closed});
    }

    let home_path = home.path.clone();
    let artifacts_path = artifacts.root.clone();
    let artifacts_db = artifacts.database();
    drop(service);
    drop(state);
    drop(home);
    let private_home_removed = !home_path.exists();
    drop(artifacts);
    let artifacts_removed = !artifacts_path.exists();
    source_before.zeroize();

    let report = json!({
        "session_id": session_id,
        "run_id": run_id,
        "prompt_path": prompt_path_str,
        "prompt_chars": prompt_text.chars().count(),
        "project": project_str,
        "evidence": evidence_str,
        "event_counts": {
            "model_requested": requested,
            "model_completed": completed,
            "tool_requested": tool_requested,
            "tool_started": tool_started,
            "tool_output": tool_output,
            "tool_completed": tool_completed,
            "tool_failed": tool_failed,
            "approval_required": approval_required,
            "approval_resolved": approval_resolved,
            "run_completed": run_completed,
            "run_failed": run_failed
        },
        "model_calls": model_calls,
        "credential_test": {"source":"Hermes credential_pool/openai-codex access_token only","fake_refresh_installed":fake_refresh_and_delivery,"private_auth_unchanged":private_auth_unchanged,"source_auth_unchanged_observed":source_auth_unchanged},
        "http_admission": http_admission,
        "delivery": delivery_report,
        "transport": {
            "refresh_attempts": refresh_attempts,
            "allowed_posts": allowed,
            "blocked": blocked,
            "business": business,
            "guardian": guardian,
            "observations": counts.observations.lock().unwrap().clone()
        },
        "tool_sequence": tool_sequence,
        "saw_write_or_patch": saw_write_or_patch,
        "saw_read": saw_read,
        "saw_terminal": saw_terminal,
        "saw_rustc_arg": saw_rustc_arg,
        "terminal_exit_codes": terminal_results,
        "produced": {
            "main_rs": main_exists,
            "test_attr_count": test_attr_count,
            "has_fn_main": has_fn_main,
            "sum_tests": sum_tests_exists,
            "sum_cli": sum_cli_exists
        },
        "harness_checks": {
            "cli_4": cli_4_ok,
            "cli_0": cli_0_ok,
            "cli_oops_nonzero": cli_oops_nonzero,
            "sum_tests_ok": sum_tests_ok
        },
        "final_assistant_present": final_present,
        "final_text_len": final_len,
        "final_head": final_head,
        "error_codes": error_codes,
        "error_statuses": error_statuses,
        "secret_cleanup": {
            "private_home_removed": private_home_removed,
            "artifacts_removed": artifacts_removed,
            "artifacts_db_outside_project": !artifacts_db.starts_with(project_str)
        }
    });
    fs::write(
        PathBuf::from(evidence_str).join("run-report.json"),
        serde_json::to_string_pretty(&report).expect("report JSON"),
    )
    .expect("write run report");
    eprintln!(
        "SAFE_REAL_RUST_SUMMARY requested={requested} completed={completed} run_completed={run_completed} run_failed={run_failed} tool_requested={tool_requested} tool_completed={tool_completed} tool_failed={tool_failed} approvals={approval_required}/{approval_resolved} model_calls={model_calls} allowed={allowed} blocked={blocked} business={business} guardian={guardian} tools={tool_sequence:?} main={main_exists} tests={test_attr_count} cli4={cli_4_ok} cli0={cli_0_ok} oops_nonzero={cli_oops_nonzero} sum_tests_ok={sum_tests_ok} final={final_present} home_removed={private_home_removed} artifacts_removed={artifacts_removed} errors={error_codes:?}/{error_statuses:?} e_root={}",
        e_root.display()
    );

    if fake_refresh_and_delivery {
        assert_eq!(refresh_attempts, 0, "no refresh endpoint attempt");
        assert!(
            private_auth_unchanged,
            "test credential must not be refreshed or replaced"
        );
        assert_eq!(
            delivery_report["final_text_matches_persisted_business_reply"], true,
            "client must receive final business delivery"
        );
        assert_eq!(delivery_report["ordered"], true);
        assert_eq!(delivery_report["listener_closed"], true);
    }
    assert_eq!(run_completed, 1, "Main must complete");
    assert_eq!(run_failed, 0, "no run failure");
    assert!(requested >= 1, "at least one model request");
    assert!(completed >= 1, "at least one model completion");
    assert_eq!(blocked, 0, "zero non-Responses attempts");
    assert!(
        allowed >= 3,
        "multi-turn needs several Responses POSTs, got {allowed}"
    );
    assert_eq!(
        model_calls, allowed as u64,
        "SDK model calls must equal real POSTs"
    );
    assert!(business >= 1, "business turns must occur");
    assert!(guardian >= 1, "Guardian ASK reviews must occur");
    assert!(
        saw_write_or_patch,
        "agent must create code with write_file/patch"
    );
    assert!(saw_read, "agent must read back with read_file");
    assert!(saw_terminal, "agent must compile/run with terminal");
    assert!(
        saw_rustc_arg,
        "agent terminal must invoke pinned rustc/sum artifacts"
    );
    let real_test_execution = messages
        .iter()
        .flat_map(|m| rustscript_agent::decode_message_blocks(&m["content"]))
        .filter(|b| {
            b.block_type == "tool_result"
                && b.is_error != Some(true)
                && b.tool_call_id
                    .as_ref()
                    .is_some_and(|id| terminal_ids.contains(id))
        })
        .any(|b| {
            let text = b.content.unwrap_or_default();
            text.contains("test result: ok.")
                && text.lines().any(|line| {
                    line.strip_prefix("test result: ok. ")
                        .and_then(|suffix| suffix.split_whitespace().next())
                        .and_then(|n| n.parse::<usize>().ok())
                        .is_some_and(|n| n >= 3)
                })
        });
    assert!(
        real_test_execution,
        "Agent terminal output must prove >=3 tests executed successfully"
    );
    assert!(main_exists, "agent must produce E/project/main.rs");
    assert!(
        test_attr_count >= 3,
        "at least three unit tests, got {test_attr_count}"
    );
    assert!(has_fn_main, "main.rs must contain fn main");
    assert!(sum_tests_exists, "agent must build sum_tests");
    assert!(sum_cli_exists, "agent must build sum_cli");
    assert!(cli_4_ok, "sum_cli 2 3 -1 must print 4");
    assert!(cli_0_ok, "sum_cli no args must print 0");
    assert!(cli_oops_nonzero, "sum_cli oops must exit nonzero");
    assert!(sum_tests_ok, "sum_tests must PASS");
    assert!(final_present, "model must continue to a final reply");
    assert!(private_home_removed, "private auth home was not removed");
    assert!(artifacts_removed, "live artifacts were not removed");
}
