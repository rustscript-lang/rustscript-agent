//! Owned, bounded loopback callback sessions for native OAuth flows.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::auth::oauth::{
    CallbackMode, CallbackWaiter, OAuthError, OAuthIoContext, PreparedCallbackSession,
    RawCallbackInput,
};

const MAX_REQUEST_BYTES: usize = 8192;
const MAX_STATE_BYTES: usize = 2048;
const MAX_CODE_BYTES: usize = 4096;
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const READ_CHUNK_BYTES: usize = 1024;
const RECEIPT: &[u8] = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nCallback received; you may close this window.";
const BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nInvalid callback request.";

/// Native callback waiter. It prepares a unique listener for each Browser flow.
#[derive(Default)]
pub struct NativeLoopbackCallbacks;

impl CallbackWaiter for NativeLoopbackCallbacks {
    fn prepare(
        &self,
        mode: CallbackMode,
        context: &OAuthIoContext,
    ) -> Result<Option<Arc<dyn PreparedCallbackSession>>, OAuthError> {
        context.check()?;
        if mode != CallbackMode::Browser {
            return Err(invalid("native callback mode is unsupported"));
        }
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| OAuthError::Transport {
                message: "loopback callback listener could not be bound".to_string(),
            })?;
        listener
            .set_nonblocking(true)
            .map_err(|_| OAuthError::Transport {
                message: "loopback callback listener setup failed".to_string(),
            })?;
        let address = listener.local_addr().map_err(|_| OAuthError::Transport {
            message: "loopback callback address is unavailable".to_string(),
        })?;
        context.check()?;
        let host = format!("127.0.0.1:{}", address.port());
        let session = NativePreparedCallbackSession {
            redirect_uri: format!("http://{host}/callback"),
            expected_host: host,
            state: Mutex::new(SessionState {
                listener: Some(listener),
                stream: None,
                request: Zeroizing::new(Vec::new()),
                response: None,
                response_offset: 0,
                parsed: None,
            }),
            revoked: AtomicBool::new(false),
            claimed: AtomicBool::new(false),
        };
        Ok(Some(Arc::new(session)))
    }

    fn wait_one(&self, _context: &OAuthIoContext) -> Result<RawCallbackInput, OAuthError> {
        Err(OAuthError::Transport {
            message: "native callback session was not prepared".to_string(),
        })
    }
}

struct SessionState {
    listener: Option<TcpListener>,
    stream: Option<TcpStream>,
    request: Zeroizing<Vec<u8>>,
    response: Option<&'static [u8]>,
    response_offset: usize,
    parsed: Option<Result<RawCallbackInput, OAuthError>>,
}

struct NativePreparedCallbackSession {
    redirect_uri: String,
    expected_host: String,
    state: Mutex<SessionState>,
    revoked: AtomicBool,
    claimed: AtomicBool,
}

impl NativePreparedCallbackSession {
    fn lock_state(&self) -> MutexGuard<'_, SessionState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn wait_inner(&self, context: &OAuthIoContext) -> Result<RawCallbackInput, OAuthError> {
        loop {
            context.check()?;
            if self.revoked.load(Ordering::Acquire) {
                return Err(transport("callback session was revoked"));
            }
            let step = {
                let mut state = self.lock_state();
                if self.revoked.load(Ordering::Acquire) {
                    return Err(transport("callback session was revoked"));
                }

                if state.response.is_some() {
                    context.check()?;
                    if self.revoked.load(Ordering::Acquire) {
                        return Err(transport("callback session was revoked"));
                    }
                    let response = state.response.expect("response was checked");
                    let response_offset = state.response_offset;
                    let response_len = response.len();
                    let stream = state
                        .stream
                        .as_mut()
                        .ok_or_else(|| transport("callback socket is unavailable"))?;
                    match stream.write(&response[response_offset..]) {
                        Ok(0) => return Err(transport("callback response write failed")),
                        Ok(written) => {
                            state.response_offset += written;
                            if state.response_offset == response_len {
                                Step::Complete(state.parsed.take().unwrap_or_else(|| {
                                    Err(transport("callback request state is unavailable"))
                                }))
                            } else {
                                Step::Pending
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            Step::Pending
                        }
                        Err(_) => return Err(transport("callback response write failed")),
                    }
                } else if state.stream.is_none() {
                    context.check()?;
                    if self.revoked.load(Ordering::Acquire) {
                        return Err(transport("callback session was revoked"));
                    }
                    let listener = state
                        .listener
                        .as_ref()
                        .ok_or_else(|| transport("callback listener is unavailable"))?;
                    match listener.accept() {
                        Ok((stream, _)) => {
                            state.listener.take();
                            stream
                                .set_nonblocking(true)
                                .map_err(|_| transport("callback socket setup failed"))?;
                            state.stream = Some(stream);
                            Step::Pending
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            Step::Pending
                        }
                        Err(_) => return Err(transport("callback listener accept failed")),
                    }
                } else {
                    context.check()?;
                    if self.revoked.load(Ordering::Acquire) {
                        return Err(transport("callback session was revoked"));
                    }
                    let remaining = MAX_REQUEST_BYTES.saturating_sub(state.request.len());
                    if remaining == 0 {
                        state.response = Some(BAD_REQUEST);
                        state.parsed = Some(Err(invalid("callback request exceeds limit")));
                        Step::Pending
                    } else {
                        let mut bytes = [0_u8; READ_CHUNK_BYTES];
                        let read_limit = remaining.min(bytes.len());
                        let stream = state.stream.as_mut().expect("accepted stream");
                        match stream.read(&mut bytes[..read_limit]) {
                            Ok(0) => {
                                state.response = Some(BAD_REQUEST);
                                state.parsed = Some(Err(invalid("callback request is incomplete")));
                                Step::Pending
                            }
                            Ok(read) => {
                                state.request.extend_from_slice(&bytes[..read]);
                                if let Some(end) = header_end(&state.request) {
                                    let parsed = parse_request(&state.request, &self.expected_host);
                                    state.response =
                                        Some(if parsed.is_ok() { RECEIPT } else { BAD_REQUEST });
                                    state.response_offset = 0;
                                    state.parsed = Some(parsed);
                                    if end + 4 != state.request.len() {
                                        state.response = Some(BAD_REQUEST);
                                        state.parsed = Some(Err(invalid(
                                            "callback request body is unsupported",
                                        )));
                                    }
                                } else if state.request.len() == MAX_REQUEST_BYTES {
                                    state.response = Some(BAD_REQUEST);
                                    state.parsed =
                                        Some(Err(invalid("callback request exceeds limit")));
                                }
                                Step::Pending
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                Step::Pending
                            }
                            Err(_) => return Err(transport("callback request read failed")),
                        }
                    }
                }
            };
            match step {
                Step::Complete(result) => return result,
                Step::Pending => pause(context)?,
            }
        }
    }
}

enum Step {
    Pending,
    Complete(Result<RawCallbackInput, OAuthError>),
}

impl PreparedCallbackSession for NativePreparedCallbackSession {
    fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    fn wait_one(&self, context: &OAuthIoContext) -> Result<RawCallbackInput, OAuthError> {
        if self.claimed.swap(true, Ordering::AcqRel) {
            self.revoke();
            return Err(transport("callback session was already consumed"));
        }
        let result = self.wait_inner(context);
        self.revoke();
        result
    }

    fn revoke(&self) {
        if self.revoked.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut state = self.lock_state();
        state.listener.take();
        if let Some(stream) = state.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        state.request.clear();
        state.response = None;
        state.response_offset = 0;
        state.parsed.take();
    }
}

impl Drop for NativePreparedCallbackSession {
    fn drop(&mut self) {
        self.revoke();
    }
}

fn pause(context: &OAuthIoContext) -> Result<(), OAuthError> {
    let remaining = context.remaining()?;
    thread::sleep(remaining.min(POLL_INTERVAL));
    context.check()
}

fn header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_request(request: &[u8], expected_host: &str) -> Result<RawCallbackInput, OAuthError> {
    let end = header_end(request).ok_or_else(|| invalid("callback request is incomplete"))?;
    if end + 4 != request.len() {
        return Err(invalid("callback request body is unsupported"));
    }
    let text = std::str::from_utf8(&request[..end])
        .map_err(|_| invalid("callback request is malformed"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| invalid("callback request is malformed"))?;
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if parts.next().is_some() || method != "GET" || version != "HTTP/1.1" {
        return Err(invalid("callback request line is unsupported"));
    }
    if target.is_empty()
        || !target.is_ascii()
        || target
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        || target.contains('#')
    {
        return Err(invalid("callback request target is malformed"));
    }
    let (path, query) = target
        .split_once('?')
        .ok_or_else(|| invalid("callback query is missing"))?;
    if path != "/callback" || query.is_empty() {
        return Err(invalid("callback path or query is unsupported"));
    }

    let mut host = None;
    let mut content_length_seen = false;
    for line in lines {
        if line.is_empty() || line.starts_with(' ') || line.starts_with('\t') {
            return Err(invalid("callback header is malformed"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("callback header is malformed"))?;
        if name.is_empty() || !name.bytes().all(is_header_name_byte) {
            return Err(invalid("callback header is malformed"));
        }
        if value
            .bytes()
            .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(invalid("callback header is malformed"));
        }
        let value = value.trim_matches(|character| character == ' ' || character == '\t');
        if name.eq_ignore_ascii_case("host") {
            if host.replace(value).is_some() || value != expected_host {
                return Err(invalid("callback host is invalid"));
            }
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length_seen || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(invalid("callback body is unsupported"));
            }
            content_length_seen = true;
            if value.parse::<u64>() != Ok(0) {
                return Err(invalid("callback body is unsupported"));
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(invalid("callback body is unsupported"));
        }
    }
    if host.is_none() {
        return Err(invalid("callback host is missing"));
    }

    let mut state = None;
    let mut code = None;
    for pair in query.split('&') {
        let (raw_key, raw_value) = pair
            .split_once('=')
            .ok_or_else(|| invalid("callback query is malformed"))?;
        if raw_key.is_empty() {
            return Err(invalid("callback query is malformed"));
        }
        let key = decode_component(raw_key)?;
        let value = decode_component(raw_value)?;
        match key.as_str() {
            "state" => {
                if state.is_some() || value.is_empty() {
                    return Err(invalid("callback state is missing or duplicated"));
                }
                if value.len() > MAX_STATE_BYTES {
                    return Err(invalid("callback query exceeds limit"));
                }
                state = Some(Zeroizing::new(value.to_string()));
            }
            "code" => {
                if code.is_some() || value.is_empty() {
                    return Err(invalid("callback code is missing or duplicated"));
                }
                if value.len() > MAX_CODE_BYTES {
                    return Err(invalid("callback query exceeds limit"));
                }
                code = Some(Zeroizing::new(value.to_string()));
            }
            _ => {}
        }
    }
    let state = state.ok_or_else(|| invalid("callback state is missing"))?;
    let code = code.ok_or_else(|| invalid("callback code is missing"))?;
    Ok(RawCallbackInput::Query {
        state: state.to_string(),
        code: code.to_string(),
    })
}

fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn decode_component(raw: &str) -> Result<Zeroizing<String>, OAuthError> {
    let input = raw.as_bytes();
    let mut decoded = Zeroizing::new(Vec::with_capacity(input.len()));
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b'%' => {
                if index + 2 >= input.len() {
                    return Err(invalid("callback query escape is malformed"));
                }
                let high = hex(input[index + 1])
                    .ok_or_else(|| invalid("callback query escape is malformed"))?;
                let low = hex(input[index + 2])
                    .ok_or_else(|| invalid("callback query escape is malformed"))?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    let value =
        std::str::from_utf8(&decoded).map_err(|_| invalid("callback query is not UTF-8"))?;
    Ok(Zeroizing::new(value.to_string()))
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn invalid(reason: &'static str) -> OAuthError {
    OAuthError::InvalidIntent {
        reason: reason.to_string(),
    }
}

fn transport(message: &'static str) -> OAuthError {
    OAuthError::Transport {
        message: message.to_string(),
    }
}
