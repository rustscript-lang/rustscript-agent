//! Native authenticated sanitized incremental SSE record security layer.
//!
//! This adapter sanitizes bounded data-only records over the accepted
//! authenticated incremental reader (`OAuthHost::start_access_stream_scoped`).
//! Each complete data item becomes either bounded strict JSON with all
//! secret-shaped keys removed, or an index into the caller-supplied public
//! marker vector. The transport framer owns EventSource syntax. Raw response
//! head values, body chunks, and SSE control fields never cross the sanitized
//! guest boundary. Provider event meaning, terminal-marker semantics, and every
//! retry/refresh/fallback decision remain RSS work.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::Value as JsonValue;

use crate::transport::sse::{FrameError, SseFramer};

use super::oauth::{
    BoundedHttpsStream, OAuthCancel, OAuthError, OAuthHost, OAuthIoContext, ProviderRequest,
    TrustedTransportPolicy, parse_strict_json_with_limits, retry_after_ms, strip_secret_keys,
};

const MAX_PUBLIC_MARKERS: usize = 16;
const MAX_PUBLIC_MARKER_BYTES: usize = 64;
const MAX_SSE_LINE_BYTES: usize = 64 * 1024;
const MAX_SSE_DATA_BYTES: usize = 64 * 1024;
const MAX_SSE_OUTPUT_BYTES: usize = 64 * 1024;
// Public event trees use the same bounded nesting budget as the public JSON
// host. Credential-response parsing retains its independent eight-level cap.
const MAX_SSE_JSON_DEPTH: usize = 64;

/// Canonical, sanitized response head. `content_type` is only ever
/// `text/event-stream`, `application/json`, or empty; no raw header value,
/// parameter, URL, or credential string is published.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct SanitizedSseHead {
    pub(crate) status: u16,
    pub(crate) content_type: String,
    pub(crate) retry_after_ms: Option<u64>,
}

/// One sanitized record. `Json` is serialized bounded strict JSON with secret
/// fields removed; `Literal` is an index into the exact caller marker vector.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum SanitizedSseRecord {
    Json(String),
    Literal(usize),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SseMode {
    EventStream,
    BufferedJson,
    Unsupported,
}

fn frame_error(error: FrameError) -> OAuthError {
    let reason = match error {
        FrameError::LineTooLong => "sse line exceeds limit",
        FrameError::DataTooLong => "sse data exceeds limit",
        FrameError::InvalidUtf8 => "sse line is not utf-8",
    };
    static_malformed(reason)
}

fn static_malformed(reason: &'static str) -> OAuthError {
    OAuthError::MalformedResponse {
        reason: reason.to_string(),
    }
}

fn transport_read_failed() -> OAuthError {
    OAuthError::Transport {
        message: "authenticated sse read failed".to_string(),
    }
}

#[allow(dead_code)]
fn map_read_error(error: OAuthError) -> OAuthError {
    match error {
        OAuthError::Cancelled
        | OAuthError::DeadlineExceeded
        | OAuthError::ResponseTooLarge { .. } => error,
        _ => transport_read_failed(),
    }
}

/// Returns only the canonical media type, never the raw header value.
#[allow(dead_code)]
fn canonical_media_type(headers: &BTreeMap<String, String>) -> Option<&'static str> {
    headers.iter().find_map(|(name, value)| {
        if !name.eq_ignore_ascii_case("content-type") {
            return None;
        }
        let media = value.split(';').next().unwrap_or("").trim();
        if media.eq_ignore_ascii_case("text/event-stream") {
            Some("text/event-stream")
        } else if media.eq_ignore_ascii_case("application/json") {
            Some("application/json")
        } else {
            None
        }
    })
}

/// Bounded validation of caller-supplied public markers with a linear,
/// small-input duplicate check. Rejection is a static invalid intent and never
/// consumes a credential slot.
#[allow(dead_code)]
fn validate_public_markers(markers: Vec<String>) -> Result<Vec<String>, OAuthError> {
    if markers.len() > MAX_PUBLIC_MARKERS {
        return Err(OAuthError::InvalidIntent {
            reason: "too many public markers".to_string(),
        });
    }
    for (index, marker) in markers.iter().enumerate() {
        if marker.is_empty() || marker.len() > MAX_PUBLIC_MARKER_BYTES {
            return Err(OAuthError::InvalidIntent {
                reason: "public marker length is invalid".to_string(),
            });
        }
        if markers[..index].iter().any(|seen| seen == marker) {
            return Err(OAuthError::InvalidIntent {
                reason: "public markers must be unique".to_string(),
            });
        }
    }
    Ok(markers)
}

#[allow(dead_code)]
pub(crate) struct SanitizedAccessSseStream {
    reader: Box<dyn BoundedHttpsStream>,
    context: OAuthIoContext,
    head: SanitizedSseHead,
    mode: SseMode,
    markers: Vec<String>,
    raw_buf: Vec<u8>,
    cursor: usize,
    framer: SseFramer,
    data: Vec<u8>,
    eof: bool,
    buffered_json_done: bool,
    terminal_error: Option<OAuthError>,
}

impl std::fmt::Debug for SanitizedAccessSseStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SanitizedAccessSseStream")
            .field("head", &self.head)
            .field("mode", &self.mode)
            .field("markers", &self.markers.len())
            .field("eof", &self.eof)
            .field("terminal", &self.terminal_error.is_some())
            .finish_non_exhaustive()
    }
}

#[allow(dead_code)]
impl OAuthHost {
    /// Open an authenticated stream without owning EventSource framing.
    pub(crate) fn start_access_sse_scoped(
        &self,
        policy: &TrustedTransportPolicy,
        request: ProviderRequest,
        access: crate::auth::store::OpaqueAccessHandle,
        owner_cancel: Arc<dyn OAuthCancel>,
        public_markers: Vec<String>,
    ) -> Result<SanitizedAccessSseStream, OAuthError> {
        let markers = validate_public_markers(public_markers)?;
        let context = self.io_context_with_cancel(policy.deadline, Arc::clone(&owner_cancel));
        let reader = self.start_access_stream_scoped(policy, request, access, owner_cancel)?;
        SanitizedAccessSseStream::from_raw(reader, context, markers)
    }
}

#[allow(dead_code)]
impl SanitizedAccessSseStream {
    fn from_raw(
        mut reader: Box<dyn BoundedHttpsStream>,
        context: OAuthIoContext,
        markers: Vec<String>,
    ) -> Result<Self, OAuthError> {
        let status = reader.head().status;
        if !(100..=599).contains(&status) {
            reader.cancel();
            return Err(static_malformed("sse response status is invalid"));
        }
        let media = canonical_media_type(&reader.head().headers);
        let has_content_type = reader
            .head()
            .headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-type"));
        let mode = match media {
            Some("text/event-stream") => SseMode::EventStream,
            Some("application/json") => SseMode::BufferedJson,
            None if (200..300).contains(&status) && !has_content_type => SseMode::EventStream,
            None if status >= 400 && !has_content_type => SseMode::BufferedJson,
            _ => SseMode::Unsupported,
        };
        let head = SanitizedSseHead {
            status,
            content_type: media.unwrap_or("").to_string(),
            retry_after_ms: retry_after_ms(&reader.head().headers),
        };
        Ok(Self {
            reader,
            context,
            head,
            mode,
            markers,
            raw_buf: Vec::new(),
            cursor: 0,
            framer: SseFramer::new(MAX_SSE_LINE_BYTES, MAX_SSE_DATA_BYTES),
            data: Vec::new(),
            eof: false,
            buffered_json_done: false,
            terminal_error: None,
        })
    }
    pub(crate) fn head(&self) -> &SanitizedSseHead {
        &self.head
    }

    pub(crate) fn read_record(&mut self) -> Result<Option<SanitizedSseRecord>, OAuthError> {
        if let Some(error) = &self.terminal_error {
            return Err(error.clone());
        }
        if self.eof {
            return Ok(None);
        }
        // Independent context check before touching any buffered or new bytes.
        if let Err(error) = self.context.check() {
            return Err(self.fail(error));
        }
        match self.mode {
            SseMode::Unsupported => {
                Err(self.fail(static_malformed("response media type is not supported")))
            }
            SseMode::EventStream => self.read_event_stream_record(),
            SseMode::BufferedJson => self.read_buffered_json_record(),
        }
    }

    /// Incremental data-only framer. Returns the first complete record and
    /// retains any unread tail without reading another transport chunk.
    fn read_event_stream_record(&mut self) -> Result<Option<SanitizedSseRecord>, OAuthError> {
        loop {
            if self.cursor >= self.raw_buf.len() {
                self.raw_buf.clear();
                self.cursor = 0;
                if self.eof {
                    // EOF discards any partial event and pending data.
                    self.clear_pending();
                    self.reader.cancel();
                    return Ok(None);
                }
                if let Err(error) = self.context.check() {
                    return Err(self.fail(error));
                }
                if let Err(error) = self.fill_chunk() {
                    return Err(self.fail(error));
                }
                continue;
            }
            let byte = self.raw_buf[self.cursor];
            self.cursor += 1;
            let data = match self.framer.push_byte(byte) {
                Ok(data) => data,
                Err(error) => return Err(self.fail(frame_error(error))),
            };
            if let Some(data) = data {
                if let Err(error) = self.context.check() {
                    return Err(self.fail(error));
                }
                let record = match self.decode_data(&data) {
                    Ok(record) => record,
                    Err(error) => return Err(self.fail(error)),
                };
                if let Err(error) = self.context.check() {
                    return Err(self.fail(error));
                }
                return Ok(Some(record));
            }
        }
    }

    /// Buffered `application/json` mode: accumulate only the bounded body until
    /// EOF, then publish exactly one sanitized JSON record.
    fn read_buffered_json_record(&mut self) -> Result<Option<SanitizedSseRecord>, OAuthError> {
        if self.buffered_json_done {
            return Ok(None);
        }
        loop {
            while self.cursor < self.raw_buf.len() {
                let byte = self.raw_buf[self.cursor];
                self.cursor += 1;
                if self.data.len() == MAX_SSE_DATA_BYTES {
                    return Err(self.fail(static_malformed("sse body exceeds data limit")));
                }
                self.data.push(byte);
            }
            self.raw_buf.clear();
            self.cursor = 0;
            if self.eof {
                self.buffered_json_done = true;
                if self.data.is_empty() {
                    self.clear_pending();
                    self.reader.cancel();
                    return Ok(None);
                }
                let data = std::mem::take(&mut self.data);
                let text = match std::str::from_utf8(&data) {
                    Ok(text) => text,
                    Err(_) => return Err(self.fail(static_malformed("sse body is not utf-8"))),
                };
                let record = match Self::sanitize_json(text) {
                    Ok(record) => record,
                    Err(error) => return Err(self.fail(error)),
                };
                self.clear_pending();
                self.reader.cancel();
                if let Err(error) = self.context.check() {
                    return Err(self.fail(error));
                }
                return Ok(Some(record));
            }
            if let Err(error) = self.context.check() {
                return Err(self.fail(error));
            }
            if let Err(error) = self.fill_chunk() {
                return Err(self.fail(error));
            }
        }
    }

    /// One raw transport read into the single reusable chunk buffer.
    fn fill_chunk(&mut self) -> Result<(), OAuthError> {
        match self.reader.read_chunk() {
            Ok(Some(bytes)) => {
                self.raw_buf = bytes;
                self.cursor = 0;
                Ok(())
            }
            Ok(None) => {
                self.eof = true;
                self.reader.cancel();
                Ok(())
            }
            Err(error) => Err(map_read_error(error)),
        }
    }

    fn decode_data(&self, data: &[u8]) -> Result<SanitizedSseRecord, OAuthError> {
        let text =
            std::str::from_utf8(data).map_err(|_| static_malformed("sse data is not utf-8"))?;
        // Exact caller literal: return only its index, never the marker text,
        // and never treat it as a stream terminator.
        if let Some(index) = self.markers.iter().position(|marker| marker == text) {
            return Ok(SanitizedSseRecord::Literal(index));
        }
        Self::sanitize_json(text)
    }

    /// Strict bounded JSON with every secret-shaped key removed at every level.
    /// Primitive JSON and non-JSON are static malformed with no raw fallback.
    fn sanitize_json(text: &str) -> Result<SanitizedSseRecord, OAuthError> {
        // The custom parser counts primitive leaves as one seed level beyond
        // container nesting; allow that leaf for the existing container cap.
        let parsed =
            parse_strict_json_with_limits(text, MAX_SSE_JSON_DEPTH + 1, Some(MAX_SSE_JSON_DEPTH))
                .map_err(|_| static_malformed("sse data is not strict json"))?;
        let cleaned = strip_secret_keys(parsed);
        if !matches!(cleaned, JsonValue::Object(_) | JsonValue::Array(_)) {
            return Err(static_malformed("sse data is not a json object or array"));
        }
        let serialized = cleaned.to_string();
        if serialized.len() > MAX_SSE_OUTPUT_BYTES {
            return Err(static_malformed("sse record exceeds output limit"));
        }
        Ok(SanitizedSseRecord::Json(serialized))
    }

    pub(crate) fn cancel(&mut self) {
        if self.terminal_error.is_none() && !self.eof {
            self.terminal_error = Some(OAuthError::Cancelled);
        }
        self.reader.cancel();
        self.clear_pending();
    }

    /// Terminalize, close the inner reader, and drop all pending bytes. Once
    /// terminal, no further raw bytes are produced.
    fn fail(&mut self, error: OAuthError) -> OAuthError {
        if self.terminal_error.is_none() {
            self.terminal_error = Some(error.clone());
        }
        self.reader.cancel();
        self.clear_pending();
        error
    }

    fn clear_pending(&mut self) {
        self.raw_buf.clear();
        self.cursor = 0;
        self.framer.discard_pending();
        self.data.clear();
    }
}

impl Drop for SanitizedAccessSseStream {
    fn drop(&mut self) {
        if !self.eof && self.terminal_error.is_none() {
            self.reader.cancel();
        }
    }
}

#[cfg(test)]
mod sanitized_sse_tests {
    use super::super::oauth::{
        BoundedHttpsStream, BoundedHttpsTransport, OAuthCancel, OAuthError, OAuthHost,
        OAuthIoContext, PreparedHttpsRequest, ProviderRequest, RawHttpsResponse,
        RawHttpsResponseHead, ScriptedBrowser, ScriptedCallback, ScriptedCancel, ScriptedClock,
        TrustedEndpoint, TrustedTransportPolicy,
    };
    use super::{SanitizedAccessSseStream, SanitizedSseRecord};
    use crate::auth::config::CredentialConfig;
    use crate::auth::store::{
        AuthStore, OpaqueAccessHandle, RefreshSecretAction, SaveCredentialRequest,
    };
    use crate::auth::token::CredentialId;
    use crate::config_file::AgentPaths;
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    const ACCESS_SECRET: &str = "SYNTHETIC_TASK7_ACCESS_TOKEN";
    const POLICY_GENERATION: u64 = 7;
    const RUN_ID: &str = "task7-native-sse-test";
    const AUTHORITY: &str = "auth.example.test";

    fn policy() -> TrustedTransportPolicy {
        TrustedTransportPolicy {
            generation: POLICY_GENERATION,
            run_id: RUN_ID.to_string(),
            deadline: Instant::now() + Duration::from_secs(120),
            endpoints: vec![TrustedEndpoint {
                authority: AUTHORITY.to_string(),
                path_prefix: "/v1".to_string(),
            }],
            allowed_header_names: ["accept", "content-type"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            transport_identity: None,
        }
    }

    fn temp_home(name: &str) -> std::path::PathBuf {
        let base = std::env::var_os("TEST_TMPDIR")
            .expect("TEST_TMPDIR must be assigned for native sse tests");
        let path = std::path::PathBuf::from(base).join(format!(
            "task7-native-sse-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("temp home");
        path
    }

    fn issue_access(name: &str) -> (AuthStore, OpaqueAccessHandle) {
        let home = temp_home(name);
        let paths = AgentPaths::from_home(home.join("home")).expect("paths");
        let store = AuthStore::open(paths).expect("store");
        let access_slot = store
            .fixture_access_slot("primary", 0, POLICY_GENERATION, RUN_ID, ACCESS_SECRET)
            .expect("access slot");
        let refresh_slot = store
            .fixture_refresh_slot("primary", 0, POLICY_GENERATION, RUN_ID, "unused-refresh")
            .expect("refresh slot");
        store
            .save_if_generation(SaveCredentialRequest::new(
                CredentialId::new("primary").expect("id"),
                0,
                POLICY_GENERATION,
                RUN_ID,
                CredentialConfig {
                    provider: "synthetic-provider".to_string(),
                    kind: "oauth".to_string(),
                    source: "synthetic-test".to_string(),
                    token_type: "Bearer".to_string(),
                    expires_at_ms: 2_500_000_000_000,
                    scopes: vec!["scope.synthetic".to_string()],
                    account_id: Some("acct.synthetic".to_string()),
                    generation: 0,
                    status: "active".to_string(),
                    last_refresh_at_ms: None,
                    has_refresh_token: true,
                },
                access_slot,
                RefreshSecretAction::Replace(refresh_slot),
            ))
            .expect("seed");
        let handle = store
            .issue_access_handle("primary", 1, POLICY_GENERATION, RUN_ID)
            .expect("access handle");
        (store, handle)
    }

    enum Injected {
        Chunk(Vec<u8>),
        Eof,
        ReadError(OAuthError),
    }

    struct InjectedState {
        starts: usize,
        reads: usize,
        eofs: usize,
        cancels: usize,
        drops: usize,
        sent: Vec<PreparedHttpsRequest>,
        queue: VecDeque<Injected>,
    }

    struct InjectedTransport {
        state: Arc<Mutex<InjectedState>>,
        status: u16,
        headers: BTreeMap<String, String>,
    }

    struct InjectedStream {
        state: Arc<Mutex<InjectedState>>,
        head: RawHttpsResponseHead,
    }

    fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    impl BoundedHttpsStream for InjectedStream {
        fn head(&self) -> &RawHttpsResponseHead {
            &self.head
        }

        fn read_chunk(&mut self) -> Result<Option<Vec<u8>>, OAuthError> {
            let mut state = locked(&self.state);
            state.reads += 1;
            match state.queue.pop_front() {
                Some(Injected::Chunk(bytes)) => Ok(Some(bytes)),
                Some(Injected::Eof) => {
                    state.eofs += 1;
                    Ok(None)
                }
                Some(Injected::ReadError(error)) => Err(error),
                // No EOF queued: a read past the supplied data is a real
                // failure, so an implementation that waits for EOF cannot pass.
                None => Err(OAuthError::Transport {
                    message: "injected stream exhausted".to_string(),
                }),
            }
        }

        fn cancel(&mut self) {
            locked(&self.state).cancels += 1;
        }
    }

    impl Drop for InjectedStream {
        fn drop(&mut self) {
            locked(&self.state).drops += 1;
        }
    }

    impl BoundedHttpsTransport for InjectedTransport {
        fn send(
            &self,
            _request: &PreparedHttpsRequest,
            _context: &OAuthIoContext,
        ) -> Result<RawHttpsResponse, OAuthError> {
            panic!("the sanitized sse path must not fall back to send");
        }

        fn start_stream(
            &self,
            request: &PreparedHttpsRequest,
            context: &OAuthIoContext,
        ) -> Result<Box<dyn BoundedHttpsStream>, OAuthError> {
            context.check()?;
            let mut state = locked(&self.state);
            state.starts += 1;
            state.sent.push(request.clone());
            drop(state);
            Ok(Box::new(InjectedStream {
                state: Arc::clone(&self.state),
                head: RawHttpsResponseHead {
                    status: self.status,
                    headers: self.headers.clone(),
                },
            }))
        }
    }

    fn mime(value: &'static str) -> Vec<(&'static str, &'static str)> {
        vec![("content-type", value)]
    }

    fn make_transport(
        status: u16,
        headers: Vec<(&str, &str)>,
        queue: Vec<Injected>,
    ) -> (Arc<InjectedTransport>, Arc<Mutex<InjectedState>>) {
        let state = Arc::new(Mutex::new(InjectedState {
            starts: 0,
            reads: 0,
            eofs: 0,
            cancels: 0,
            drops: 0,
            sent: Vec::new(),
            queue: VecDeque::from(queue),
        }));
        let headers = headers
            .into_iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        (
            Arc::new(InjectedTransport {
                state: Arc::clone(&state),
                status,
                headers,
            }),
            state,
        )
    }

    fn make_host(
        transport: Arc<InjectedTransport>,
        clock: &Arc<ScriptedClock>,
        cancel: &Arc<ScriptedCancel>,
    ) -> OAuthHost {
        OAuthHost::new(
            transport,
            Arc::new(ScriptedCallback::new()),
            Arc::new(ScriptedBrowser::new()),
            Arc::clone(clock) as Arc<dyn super::super::oauth::OAuthClock>,
            Arc::clone(cancel) as Arc<dyn OAuthCancel>,
        )
    }

    fn owner(cancel: &Arc<ScriptedCancel>) -> Arc<dyn OAuthCancel> {
        Arc::clone(cancel) as Arc<dyn OAuthCancel>
    }

    fn get(path: &str) -> ProviderRequest {
        ProviderRequest {
            method: "GET".to_string(),
            path: path.to_string(),
            public_headers: BTreeMap::new(),
            public_body: String::new(),
            credential_id: "primary".to_string(),
        }
    }

    fn start_stream(
        host: &OAuthHost,
        access: OpaqueAccessHandle,
        cancel: &Arc<ScriptedCancel>,
        markers: Vec<String>,
    ) -> SanitizedAccessSseStream {
        host.start_access_sse_scoped(&policy(), get("/v1/stream"), access, owner(cancel), markers)
            .expect("sanitized sse starts")
    }

    fn expect_record(result: Result<Option<SanitizedSseRecord>, OAuthError>) -> SanitizedSseRecord {
        match result {
            Ok(Some(record)) => record,
            other => panic!("expected a sanitized record, got {other:?}"),
        }
    }

    fn expect_end(result: Result<Option<SanitizedSseRecord>, OAuthError>) {
        match result {
            Ok(None) => {}
            other => panic!("expected end of stream, got {other:?}"),
        }
    }

    fn expect_error(result: Result<Option<SanitizedSseRecord>, OAuthError>) -> OAuthError {
        match result {
            Ok(value) => panic!("expected a safe error, got {value:?}"),
            Err(error) => error,
        }
    }

    fn expect_start_error(result: Result<SanitizedAccessSseStream, OAuthError>) -> OAuthError {
        match result {
            Ok(_) => panic!("expected the sanitized sse start to be denied"),
            Err(error) => error,
        }
    }

    fn json_text(record: SanitizedSseRecord) -> String {
        match record {
            SanitizedSseRecord::Json(text) => text,
            other => panic!("expected a sanitized json record, got {other:?}"),
        }
    }

    #[test]
    fn provider_stream_accepts_many_bounded_records_beyond_credential_body_cap() {
        let (_store, access) = issue_access("stream-total");
        let chunk = format!("data: {{\"text\":\"{}\"}}\n\n", "x".repeat(1024)).into_bytes();
        let mut queue: Vec<_> = (0..128).map(|_| Injected::Chunk(chunk.clone())).collect();
        queue.push(Injected::Eof);
        let (transport, _) = make_transport(200, mime("text/event-stream"), queue);
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let host = make_host(transport, &clock, &cancel);
        let mut stream = start_stream(&host, access, &cancel, vec![]);
        for _ in 0..128 {
            expect_record(stream.read_record());
        }
        expect_end(stream.read_record());
    }

    #[test]
    fn provider_stream_total_cap_remains_enforced_and_credential_io_stays_small() {
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let context = OAuthIoContext::new(
            Instant::now() + Duration::from_secs(3),
            clock.clone(),
            cancel.clone(),
        );
        assert_eq!(context.max_response_body_bytes(), 64 * 1024);
        let (_store, access) = issue_access("stream-over-total");
        let (transport, state) = make_transport(
            200,
            mime("text/event-stream"),
            vec![Injected::Chunk(vec![b' '; 8 * 1024 * 1024 + 1])],
        );
        let host = make_host(transport, &clock, &cancel);
        let mut stream = start_stream(&host, access, &cancel, vec![]);
        assert!(
            matches!(expect_error(stream.read_record()), OAuthError::ResponseTooLarge { max_bytes } if max_bytes == 8 * 1024 * 1024)
        );
        assert_eq!(locked(&state).cancels, 1);
    }

    #[test]
    fn sanitized_sse_publishes_first_json_record_before_withheld_eof() {
        let (_store, access) = issue_access("first");
        let chunk = b"data: {\"type\":\"delta\",\"text\":\"hi\",\"access_token\":\"SYNTHETIC_SECRET\",\"nested\":{\"Authorization\":\"secret\"},\"list\":[{\"Password\":\"p\"}]}\n\n"
            .to_vec();
        let (transport, state) =
            make_transport(200, mime("text/event-stream"), vec![Injected::Chunk(chunk)]);
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let host = make_host(transport, &clock, &cancel);

        let mut stream = start_stream(&host, access.clone(), &cancel, vec!["DONE".to_string()]);

        assert_eq!(stream.head().status, 200);
        assert_eq!(stream.head().content_type, "text/event-stream");
        {
            let state = locked(&state);
            assert_eq!(state.starts, 1, "exactly one incremental start");
            assert_eq!(state.sent.len(), 1);
            assert_eq!(
                state.sent[0]
                    .headers
                    .get("authorization")
                    .map(String::as_str),
                Some("Bearer SYNTHETIC_TASK7_ACCESS_TOKEN"),
                "the shared helper injects the final Bearer"
            );
            assert_eq!(
                state.sent[0].url, "https://auth.example.test/v1/stream",
                "authority comes from trusted policy, not the caller"
            );
        }

        let text = json_text(expect_record(stream.read_record()));
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("sanitized json parses");
        assert_eq!(parsed["type"], "delta");
        assert_eq!(parsed["text"], "hi");
        assert!(parsed.get("access_token").is_none());
        assert!(parsed["nested"].get("Authorization").is_none());
        assert!(parsed["list"][0].get("Password").is_none());
        assert!(!text.contains("SYNTHETIC_SECRET"));
        {
            let state = locked(&state);
            assert_eq!(
                state.reads, 1,
                "the first record needs exactly one raw read"
            );
            assert_eq!(
                state.eofs, 0,
                "EOF is not observed before the record is published"
            );
        }

        // Only now add the marker event and EOF.
        {
            let mut state = locked(&state);
            state
                .queue
                .push_back(Injected::Chunk(b"data: DONE\n\n".to_vec()));
            state.queue.push_back(Injected::Eof);
        }
        assert!(matches!(
            expect_record(stream.read_record()),
            SanitizedSseRecord::Literal(0)
        ));
        expect_end(stream.read_record());
        assert_eq!(locked(&state).eofs, 1);

        assert_eq!(
            access
                .consume()
                .expect_err("one-shot access is consumed")
                .code(),
            "handle_replayed"
        );
    }

    #[test]
    fn sanitized_sse_returns_records_in_order_then_honors_cancel_before_buffered_record() {
        let (_store, access) = issue_access("cancel");
        let chunk = b"data: {\"a\":1}\n\ndata: {\"b\":2}\n\n".to_vec();
        let (transport, state) =
            make_transport(200, mime("text/event-stream"), vec![Injected::Chunk(chunk)]);
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let host = make_host(transport, &clock, &cancel);
        let mut stream = start_stream(&host, access, &cancel, vec!["DONE".to_string()]);

        let first = json_text(expect_record(stream.read_record()));
        assert_eq!(first, "{\"a\":1}");
        assert_eq!(
            locked(&state).reads,
            1,
            "the second record is already buffered"
        );

        cancel.cancel();
        let error = expect_error(stream.read_record());
        assert_eq!(error.code(), "cancelled");
        assert_eq!(
            locked(&state).reads,
            1,
            "no new raw read after cancellation"
        );
        assert!(locked(&state).cancels >= 1, "the inner reader is closed");

        let again = expect_error(stream.read_record());
        assert_eq!(again, error, "terminal state is stable");
        assert_eq!(
            locked(&state).reads,
            1,
            "the buffered second record is never published"
        );
    }

    #[test]
    fn sanitized_sse_honors_deadline_before_buffered_record() {
        let (_store, access) = issue_access("deadline");
        let chunk = b"data: {\"a\":1}\n\ndata: {\"b\":2}\n\n".to_vec();
        let (transport, state) =
            make_transport(200, mime("text/event-stream"), vec![Injected::Chunk(chunk)]);
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let host = make_host(transport, &clock, &cancel);
        let mut stream = start_stream(&host, access, &cancel, vec!["DONE".to_string()]);

        assert_eq!(json_text(expect_record(stream.read_record())), "{\"a\":1}");
        clock.expire();
        assert_eq!(
            expect_error(stream.read_record()).code(),
            "deadline_exceeded"
        );
        assert_eq!(locked(&state).reads, 1);
    }

    #[test]
    fn sanitized_sse_framing_handles_bom_crlf_split_utf8_controls_and_discards_partial_eof() {
        let (_store, access) = issue_access("framing");
        let mut full: Vec<u8> = Vec::new();
        full.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
        full.extend_from_slice("data: {\"greeting\":\"hi \u{1F600}\"}\r\n".as_bytes());
        full.extend_from_slice(b": keep-alive comment\r\n");
        full.extend_from_slice(b"event: message\r\n");
        full.extend_from_slice(b"id: 42\r\n");
        full.extend_from_slice(b"retry: 1000\r\n");
        full.extend_from_slice(b"\r\n");
        full.extend_from_slice(b"data: DONE\n\n");
        full.extend_from_slice(b"data: {\"partial\":true}");

        let emoji = "\u{1F600}".as_bytes();
        let emoji_start = full
            .windows(emoji.len())
            .position(|window| window == emoji)
            .expect("emoji present");
        let crlf = full
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("crlf present");

        let mut splits = vec![1usize, emoji_start + 2, crlf + 1];
        splits.sort_unstable();
        let mut queue: Vec<Injected> = Vec::new();
        let mut start = 0usize;
        for split in splits {
            queue.push(Injected::Chunk(full[start..split].to_vec()));
            start = split;
        }
        queue.push(Injected::Chunk(full[start..].to_vec()));
        queue.push(Injected::Eof);

        let (transport, _state) = make_transport(200, mime("text/event-stream"), queue);
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let host = make_host(transport, &clock, &cancel);
        let mut stream = start_stream(
            &host,
            access,
            &cancel,
            vec!["IGNORED".to_string(), "DONE".to_string()],
        );

        let text = json_text(expect_record(stream.read_record()));
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("json parses");
        assert_eq!(parsed["greeting"], "hi \u{1F600}");
        assert_eq!(parsed.as_object().expect("object").len(), 1);
        assert!(!text.contains("message"));
        assert!(!text.contains("1000"));
        assert!(matches!(
            expect_record(stream.read_record()),
            SanitizedSseRecord::Literal(1)
        ));
        // The final unterminated partial event is discarded at EOF.
        expect_end(stream.read_record());
    }

    #[test]
    fn sanitized_sse_fails_closed_and_stays_terminal() {
        let mut deep = String::new();
        for _ in 0..=super::MAX_SSE_JSON_DEPTH {
            deep.push_str("{\"a\":");
        }
        deep.push('1');
        for _ in 0..=super::MAX_SSE_JSON_DEPTH {
            deep.push('}');
        }
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("malformed-json", b"data: {broken\n\n".to_vec()),
            ("duplicate-key", b"data: {\"a\":1,\"a\":2}\n\n".to_vec()),
            ("primitive", b"data: 5\n\n".to_vec()),
            ("non-json", b"data: hello world\n\n".to_vec()),
            ("empty-data", b"data:\n\n".to_vec()),
            (
                "malformed-utf8",
                vec![b'd', b'a', b't', b'a', b':', b' ', 0xFF, 0xFE, b'\n', b'\n'],
            ),
            ("deep-json", format!("data: {deep}\n\n").into_bytes()),
            (
                "serialized-output-limit",
                format!("data: [{}]\n\n", vec!["1e10"; 7000].join(",")).into_bytes(),
            ),
        ];

        for (name, chunk) in cases {
            let (_store, access) = issue_access(&format!("fail-{name}"));
            let (transport, state) = make_transport(
                200,
                mime("text/event-stream"),
                vec![
                    Injected::Chunk(chunk),
                    Injected::Chunk(b"data: {\"after\":true}\n\n".to_vec()),
                    Injected::Eof,
                ],
            );
            let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
            let cancel = Arc::new(ScriptedCancel::new());
            let host = make_host(transport, &clock, &cancel);
            let mut stream = start_stream(&host, access, &cancel, vec!["DONE".to_string()]);

            let error = expect_error(stream.read_record());
            assert_eq!(error.code(), "malformed_response", "case {name}");
            assert!(
                format!("{error:?}").len() < 200,
                "diagnostics carry no raw payload: {name}"
            );
            assert_eq!(
                locked(&state).reads,
                1,
                "fuses without further reads: {name}"
            );
            assert!(
                locked(&state).cancels >= 1,
                "closes the inner reader: {name}"
            );
            let again = expect_error(stream.read_record());
            assert_eq!(again, error, "terminal error is stable: {name}");
            assert_eq!(locked(&state).reads, 1, "no revival read: {name}");
        }
    }

    #[test]
    fn sanitized_sse_redacts_all_transport_read_details() {
        for detail in [
            OAuthError::MalformedResponse {
                reason: "PRIVATE_READ_DIAGNOSTIC".to_string(),
            },
            OAuthError::InvalidIntent {
                reason: "PRIVATE_READ_DIAGNOSTIC".to_string(),
            },
            OAuthError::Transport {
                message: "PRIVATE_READ_DIAGNOSTIC".to_string(),
            },
        ] {
            let (_store, access) = issue_access("read-detail");
            let (transport, state) = make_transport(
                200,
                mime("text/event-stream"),
                vec![
                    Injected::ReadError(detail),
                    Injected::Chunk(b"data: {\"after\":true}\n\n".to_vec()),
                ],
            );
            let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
            let cancel = Arc::new(ScriptedCancel::new());
            let host = make_host(transport, &clock, &cancel);
            let mut stream = start_stream(&host, access, &cancel, Vec::new());
            let error = expect_error(stream.read_record());
            assert!(
                !format!("{error:?} {error}").contains("PRIVATE_READ_DIAGNOSTIC"),
                "transport read diagnostics must stay private"
            );
            assert_eq!(error.code(), "transport_error");
            assert_eq!(expect_error(stream.read_record()), error);
            assert_eq!(locked(&state).reads, 1);
            assert!(locked(&state).cancels >= 1);
        }
    }

    #[test]
    fn sanitized_sse_raw_cap_is_bounded_by_the_authenticated_wrapper() {
        let (_store, access) = issue_access("cap");
        let (transport, state) = make_transport(
            200,
            mime("text/event-stream"),
            vec![
                // Many short comment lines stay under per-record framing
                // limits while crossing the independent stream total.
                Injected::Chunk(b": heartbeat\n".repeat(5 * 1024 * 1024 / 12)),
                Injected::Chunk(b": heartbeat\n".repeat(5 * 1024 * 1024 / 12)),
                Injected::Eof,
            ],
        );
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let host = make_host(transport, &clock, &cancel);
        let mut stream = start_stream(&host, access, &cancel, vec!["DONE".to_string()]);

        let error = expect_error(stream.read_record());
        assert_eq!(error.code(), "response_too_large");
        assert!(locked(&state).cancels >= 1);
        assert_eq!(
            expect_error(stream.read_record()).code(),
            "response_too_large"
        );
    }

    #[test]
    fn sanitized_sse_head_is_canonical_and_strips_private_headers() {
        let (_store, access) = issue_access("head");
        let headers = vec![
            ("content-type", "text/event-stream; charset=utf-8"),
            ("retry-after", "3"),
            ("set-cookie", "session=SYNTHETIC_COOKIE"),
            ("authorization", "Bearer SYNTHETIC_HEADER"),
            ("x-private", "SYNTHETIC_RAW"),
        ];
        let (transport, _state) = make_transport(429, headers, vec![Injected::Eof]);
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let host = make_host(transport, &clock, &cancel);
        let mut stream = start_stream(&host, access, &cancel, vec!["DONE".to_string()]);

        assert_eq!(stream.head().status, 429);
        assert_eq!(stream.head().content_type, "text/event-stream");
        assert_eq!(stream.head().retry_after_ms, Some(3000));
        let debug = format!("{:?}", stream.head());
        assert!(!debug.contains("SYNTHETIC_COOKIE"));
        assert!(!debug.contains("SYNTHETIC_HEADER"));
        assert!(!debug.contains("SYNTHETIC_RAW"));
        assert!(!debug.contains("charset"));
        expect_end(stream.read_record());
    }

    #[test]
    fn sanitized_sse_json_mode_preserves_status_and_sanitizes_error_body() {
        let (_store, access) = issue_access("json-error");
        let body = br#"{"error":"bad_request","access_token":"SYNTHETIC_SECRET","nested":{"Cookie":"c","Refresh_Token":"r"}}"#
            .to_vec();
        let (transport, _state) = make_transport(
            400,
            vec![("content-type", "application/json")],
            vec![Injected::Chunk(body), Injected::Eof],
        );
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let host = make_host(transport, &clock, &cancel);
        let mut stream = start_stream(&host, access, &cancel, vec!["DONE".to_string()]);

        assert_eq!(stream.head().status, 400);
        assert_eq!(stream.head().content_type, "application/json");
        let text = json_text(expect_record(stream.read_record()));
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("json parses");
        assert_eq!(parsed["error"], "bad_request");
        assert!(parsed.get("access_token").is_none());
        assert!(parsed["nested"].get("Cookie").is_none());
        assert!(parsed["nested"].get("Refresh_Token").is_none());
        assert!(!text.contains("SYNTHETIC_SECRET"));
        expect_end(stream.read_record());
    }

    #[test]
    fn sanitized_sse_eof_remains_terminal_after_context_changes() {
        for media in ["text/event-stream", "application/json"] {
            let (_store, access) = issue_access("terminal-eof");
            let (transport, state) = make_transport(200, mime(media), vec![Injected::Eof]);
            let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
            let cancel = Arc::new(ScriptedCancel::new());
            let host = make_host(transport, &clock, &cancel);
            let mut stream = start_stream(&host, access, &cancel, Vec::new());
            expect_end(stream.read_record());
            cancel.cancel();
            clock.expire();
            expect_end(stream.read_record());
            stream.cancel();
            expect_end(stream.read_record());
            assert_eq!(locked(&state).reads, 1);
            assert!(locked(&state).cancels >= 1);
        }
    }

    #[test]
    fn sanitized_sse_json_mode_empty_body_is_eof() {
        let (_store, access) = issue_access("json-empty");
        let (transport, _state) = make_transport(
            200,
            vec![("content-type", "application/json")],
            vec![Injected::Eof],
        );
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let host = make_host(transport, &clock, &cancel);
        let mut stream = start_stream(&host, access, &cancel, vec!["DONE".to_string()]);
        expect_end(stream.read_record());
    }

    #[test]
    fn sanitized_sse_missing_mime_success_parses_strict_event_stream() {
        let (_store, access) = issue_access("missing-mime-success");
        let body = b"data: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"delta\":\"OK\"}\n\n";
        let (transport, state) = make_transport(
            200,
            Vec::new(),
            vec![Injected::Chunk(body.to_vec()), Injected::Eof],
        );
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let host = make_host(transport, &clock, &cancel);
        let mut stream = start_stream(&host, access, &cancel, vec!["DONE".to_string()]);

        assert_eq!(stream.head().status, 200);
        assert_eq!(stream.head().content_type, "");
        let text = json_text(expect_record(stream.read_record()));
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("json parses");
        assert_eq!(parsed["type"], "response.output_text.delta");
        assert_eq!(parsed["delta"], "OK");
        assert_eq!(locked(&state).reads, 1);
        expect_end(stream.read_record());
    }

    #[test]
    fn responses_moderation_metadata_is_a_valid_public_sse_record() {
        use serde_json::json;
        // Shape reproduced from a captured public response.metadata record;
        // no account identifiers or captured moderation values are retained.
        let event = json!({
            "type": "response.metadata",
            "metadata": {"openai_chatgpt_moderation_metadata": {"prompt": {
                "omnimod": {"outputs": [{"results": [{"category_flags": {
                    "safe_fixture": false, "access_token": "SYNTHETIC_SECRET"
                }}]}]}
            }}}
        });
        let text = event.to_string();
        assert!(
            super::super::oauth::parse_strict_json(&text).is_err(),
            "credential JSON must keep its existing small bound"
        );
        let record = SanitizedAccessSseStream::sanitize_json(&text)
            .expect("valid bounded public metadata must not abort the provider stream");
        let super::SanitizedSseRecord::Json(public) = record else {
            panic!("expected public JSON");
        };
        assert!(!public.contains("SYNTHETIC_SECRET"));
        assert!(!public.contains("access_token"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&public).unwrap()["type"],
            "response.metadata"
        );
    }

    #[test]
    fn sanitized_sse_public_depth_bound_keeps_credential_limit_and_redacts() {
        assert_eq!(
            super::super::oauth::MAX_JSON_DEPTH,
            8,
            "credential bound must remain unchanged"
        );
        assert_eq!(
            super::MAX_SSE_JSON_DEPTH,
            64,
            "public JSON nesting is explicitly bounded"
        );
        let mut json = r#"{"access_token":"SYNTHETIC_SECRET"}"#.to_string();
        for _ in 0..(super::MAX_SSE_JSON_DEPTH - 1) {
            json = format!("{{\"nested\":{json}}}");
        }
        assert!(super::super::oauth::parse_strict_json(&json).is_err());

        let (_store, access) = issue_access("public-depth-limit");
        let body = format!("data: {json}\n\n").into_bytes();
        let (transport, state) =
            make_transport(200, Vec::new(), vec![Injected::Chunk(body), Injected::Eof]);
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let host = make_host(transport, &clock, &cancel);
        let mut stream = start_stream(&host, access, &cancel, vec!["DONE".to_string()]);

        let sanitized = json_text(expect_record(stream.read_record()));
        assert!(!sanitized.contains("SYNTHETIC_SECRET"));
        let mut parsed: serde_json::Value =
            serde_json::from_str(&sanitized).expect("sanitized JSON parses");
        for _ in 0..(super::MAX_SSE_JSON_DEPTH - 1) {
            parsed = parsed["nested"].clone();
        }
        assert!(parsed.get("access_token").is_none());
        assert_eq!(locked(&state).reads, 1);
        expect_end(stream.read_record());

        let mut empty_over_limit_object = "{}".to_string();
        let mut empty_over_limit_array = "[]".to_string();
        let mut mixed_over_limit_container = "[]".to_string();
        for depth in 1..=super::MAX_SSE_JSON_DEPTH {
            empty_over_limit_object = format!("{{\"nested\":{empty_over_limit_object}}}");
            empty_over_limit_array = format!("[{empty_over_limit_array}]");
            mixed_over_limit_container = if depth % 2 == 0 {
                format!("{{\"nested\":{mixed_over_limit_container}}}")
            } else {
                format!("[{mixed_over_limit_container}]")
            };
        }
        for candidate in [
            &empty_over_limit_object,
            &empty_over_limit_array,
            &mixed_over_limit_container,
        ] {
            assert!(
                super::super::oauth::parse_strict_json(candidate).is_err(),
                "general OAuth strict seed depth remains eight"
            );
        }
        for (label, json) in [
            ("empty-over-limit-object", empty_over_limit_object),
            ("empty-over-limit-array", empty_over_limit_array),
            ("mixed-over-limit-container", mixed_over_limit_container),
        ] {
            let (_store, access) = issue_access(label);
            let body = format!("data: {json}\n\n").into_bytes();
            let (transport, _state) =
                make_transport(200, Vec::new(), vec![Injected::Chunk(body), Injected::Eof]);
            let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
            let cancel = Arc::new(ScriptedCancel::new());
            let host = make_host(transport, &clock, &cancel);
            let mut stream = start_stream(&host, access, &cancel, vec!["DONE".to_string()]);
            assert_eq!(
                expect_error(stream.read_record()).code(),
                "malformed_response",
                "{label} must be rejected beyond the public container bound"
            );
        }

        let mut too_deep = r#"{"value":"leaf"}"#.to_string();
        for _ in 0..super::MAX_SSE_JSON_DEPTH {
            too_deep = format!("{{\"nested\":{too_deep}}}");
        }
        let body = format!("data: {too_deep}\n\n").into_bytes();
        let (transport, _state) =
            make_transport(200, Vec::new(), vec![Injected::Chunk(body), Injected::Eof]);
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let host = make_host(transport, &clock, &cancel);
        let (_depth_store, depth_access) = issue_access("public-depth-over-limit");
        let mut stream = start_stream(&host, depth_access, &cancel, vec!["DONE".to_string()]);
        assert_eq!(
            expect_error(stream.read_record()).code(),
            "malformed_response"
        );
    }

    #[test]
    fn sanitized_sse_missing_mime_error_reads_bounded_json_body() {
        let (_store, access) = issue_access("missing-mime-error");
        let body = br#"{"error":{"type":"invalid_request_error","message":"safe error","access_token":"SYNTHETIC_SECRET"}}"#.to_vec();
        let (transport, state) =
            make_transport(400, Vec::new(), vec![Injected::Chunk(body), Injected::Eof]);
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let host = make_host(transport, &clock, &cancel);
        let mut stream = start_stream(&host, access, &cancel, vec!["DONE".to_string()]);

        assert_eq!(stream.head().status, 400);
        assert_eq!(stream.head().content_type, "");
        let text = json_text(expect_record(stream.read_record()));
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("json parses");
        assert_eq!(parsed["error"]["type"], "invalid_request_error");
        assert!(parsed["error"].get("access_token").is_none());
        assert!(!text.contains("SYNTHETIC_SECRET"));
        assert_eq!(locked(&state).reads, 2);
        expect_end(stream.read_record());
    }

    #[test]
    fn sanitized_sse_unsupported_mime_keeps_head_and_fails_closed_without_reading() {
        let (_store, access) = issue_access("unsupported");
        let (transport, state) = make_transport(
            500,
            vec![("content-type", "text/plain")],
            vec![Injected::Chunk(b"raw body".to_vec())],
        );
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let host = make_host(transport, &clock, &cancel);
        let mut stream = start_stream(&host, access, &cancel, vec!["DONE".to_string()]);

        assert_eq!(stream.head().status, 500);
        assert_eq!(stream.head().content_type, "");
        let error = expect_error(stream.read_record());
        assert_eq!(error.code(), "malformed_response");
        assert_eq!(
            locked(&state).reads,
            0,
            "no body bytes are read for an unsupported mime"
        );
        assert!(locked(&state).cancels >= 1);
        assert_eq!(expect_error(stream.read_record()), error);
    }

    #[test]
    fn sanitized_sse_invalid_status_is_rejected_before_head_publication() {
        let (_store, access) = issue_access("status");
        let (transport, _state) = make_transport(
            42,
            vec![("content-type", "text/event-stream")],
            vec![Injected::Eof],
        );
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let host = make_host(transport, &clock, &cancel);
        let error = expect_start_error(host.start_access_sse_scoped(
            &policy(),
            get("/v1/stream"),
            access,
            owner(&cancel),
            vec!["DONE".to_string()],
        ));
        assert_eq!(error.code(), "malformed_response");
    }

    #[test]
    fn sanitized_sse_rejects_invalid_public_markers_before_consuming_credentials() {
        let long = "x".repeat(65);
        let too_many: Vec<String> = (0..17).map(|index| format!("m{index}")).collect();
        let cases: Vec<(&str, Vec<String>)> = vec![
            ("empty", vec![String::new()]),
            ("oversize", vec![long]),
            ("too-many", too_many),
            ("duplicate", vec!["DUP".to_string(), "DUP".to_string()]),
        ];

        for (name, markers) in cases {
            let (_store, access) = issue_access(&format!("markers-{name}"));
            let (transport, state) =
                make_transport(200, mime("text/event-stream"), vec![Injected::Eof]);
            let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
            let cancel = Arc::new(ScriptedCancel::new());
            let host = make_host(transport, &clock, &cancel);
            let error = expect_start_error(host.start_access_sse_scoped(
                &policy(),
                get("/v1/stream"),
                access.clone(),
                owner(&cancel),
                markers,
            ));
            assert_eq!(error.code(), "invalid_intent", "case {name}");
            assert_eq!(
                locked(&state).starts,
                0,
                "markers gate the raw start: {name}"
            );
            access
                .validate()
                .expect("access stays live after marker rejection");
        }
    }

    #[test]
    fn sanitized_sse_cancel_and_drop_close_the_inner_reader() {
        let (_store, access) = issue_access("drop");
        let (transport, state) = make_transport(
            200,
            mime("text/event-stream"),
            vec![
                Injected::Chunk(b"data: {\"a\":1}\n\n".to_vec()),
                Injected::Eof,
            ],
        );
        let clock = Arc::new(ScriptedClock::new(1_900_000_000_000));
        let cancel = Arc::new(ScriptedCancel::new());
        let host = make_host(transport, &clock, &cancel);
        let mut stream = start_stream(&host, access, &cancel, vec!["DONE".to_string()]);

        assert_eq!(json_text(expect_record(stream.read_record())), "{\"a\":1}");
        stream.cancel();
        assert!(locked(&state).cancels >= 1);
        assert_eq!(expect_error(stream.read_record()).code(), "cancelled");
        drop(stream);
        assert!(locked(&state).drops >= 1, "the inner reader is released");
    }
}
