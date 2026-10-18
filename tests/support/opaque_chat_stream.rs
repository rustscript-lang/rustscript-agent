use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rustscript_agent::auth::oauth::{
    BoundedHttpsStream, BoundedHttpsTransport, OAuthError, OAuthIoContext, PreparedHttpsRequest,
    RawHttpsResponse, RawHttpsResponseHead,
};

#[derive(Default)]
pub struct StreamCounts {
    pub starts: AtomicUsize,
    pub reads: AtomicUsize,
    pub eof: AtomicUsize,
    pub cancels: AtomicUsize,
    pub drops: AtomicUsize,
    pub sent: Mutex<Vec<PreparedHttpsRequest>>,
}

pub struct StreamTransport {
    pub counts: Arc<StreamCounts>,
    head: RawHttpsResponseHead,
    chunks: Mutex<VecDeque<Vec<u8>>>,
    allow_eof: bool,
    /// Test-only injected transport read failure detail. The public result must
    /// never echo it.
    read_error: Option<String>,
    /// Test-only hook invoked on every raw read, used for deterministic clock
    /// jumps or cancellation during a live stream (no sleeps, no threads).
    on_read: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl StreamTransport {
    pub fn new(status: u16, content_type: &str, chunks: Vec<Vec<u8>>, allow_eof: bool) -> Self {
        Self {
            counts: Arc::new(StreamCounts::default()),
            head: RawHttpsResponseHead {
                status,
                headers: BTreeMap::from([("content-type".to_owned(), content_type.to_owned())]),
            },
            chunks: Mutex::new(chunks.into()),
            allow_eof,
            read_error: None,
            on_read: None,
        }
    }

    /// Fail one raw read with a private detail that must not be published.
    /// Only the direct-entry suite injects this; the default suite keeps the
    /// plain constructor, so the sibling binary would otherwise dead-code it.
    #[allow(dead_code)]
    pub fn with_read_error(mut self, message: &str) -> Self {
        self.read_error = Some(message.to_owned());
        self
    }

    /// Observe every raw read from the test side (deterministic expiry).
    /// Only the direct-entry suite installs this hook; the default suite does
    /// not, so the sibling binary would otherwise dead-code it.
    #[allow(dead_code)]
    pub fn with_read_callback(mut self, callback: impl Fn() + Send + Sync + 'static) -> Self {
        self.on_read = Some(Arc::new(callback));
        self
    }
}

impl BoundedHttpsTransport for StreamTransport {
    fn send(
        &self,
        _: &PreparedHttpsRequest,
        _: &OAuthIoContext,
    ) -> Result<RawHttpsResponse, OAuthError> {
        panic!("opaque streaming must never use buffered send")
    }

    fn start_stream(
        &self,
        request: &PreparedHttpsRequest,
        _: &OAuthIoContext,
    ) -> Result<Box<dyn BoundedHttpsStream>, OAuthError> {
        self.counts.starts.fetch_add(1, Ordering::SeqCst);
        self.counts
            .sent
            .lock()
            .expect("record request")
            .push(request.clone());
        Ok(Box::new(StreamReader {
            counts: Arc::clone(&self.counts),
            head: RawHttpsResponseHead {
                status: self.head.status,
                headers: self.head.headers.clone(),
            },
            chunks: std::mem::take(&mut *self.chunks.lock().expect("stream chunks")),
            allow_eof: self.allow_eof,
            read_error: self.read_error.clone(),
            on_read: self.on_read.clone(),
        }))
    }
}

struct StreamReader {
    counts: Arc<StreamCounts>,
    head: RawHttpsResponseHead,
    chunks: VecDeque<Vec<u8>>,
    allow_eof: bool,
    read_error: Option<String>,
    on_read: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl BoundedHttpsStream for StreamReader {
    fn head(&self) -> &RawHttpsResponseHead {
        &self.head
    }

    fn read_chunk(&mut self) -> Result<Option<Vec<u8>>, OAuthError> {
        self.counts.reads.fetch_add(1, Ordering::SeqCst);
        if let Some(callback) = &self.on_read {
            callback();
        }
        if let Some(chunk) = self.chunks.pop_front() {
            Ok(Some(chunk))
        } else if let Some(message) = &self.read_error {
            Err(OAuthError::Transport {
                message: message.clone(),
            })
        } else if self.allow_eof {
            self.counts.eof.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        } else {
            Err(OAuthError::Transport {
                message: "unexpected read past terminal marker".to_owned(),
            })
        }
    }

    fn cancel(&mut self) {
        self.counts.cancels.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for StreamReader {
    fn drop(&mut self) {
        self.counts.drops.fetch_add(1, Ordering::SeqCst);
    }
}
