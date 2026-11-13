//! Fixed public vocabulary for native stream transport failures.
//!
//! The native HTTPS transport already classifies each body and connection
//! error into a fixed category. That category is otherwise lost when the typed
//! [`OAuthError`] is flattened to the public transport code, so the stream host
//! captures it here before flattening and renders only these fixed values.
//! Arbitrary transport text is never copied into a category.

use crate::auth::oauth::OAuthError;

/// Fixed phase token for a failure while opening the authenticated stream.
pub(crate) const PHASE_START: &str = "start";
/// Fixed phase token for a failure while reading an opened stream.
pub(crate) const PHASE_READ: &str = "read";

/// Exact native transport category vocabulary. Values outside this list are
/// unknown text and are never published.
const NATIVE_TRANSPORT_CATEGORIES: &[&str] = &[
    "authenticated sse read failed",
    "native_https_body_closed",
    "native_https_body_failed",
    "native_https_body_io_eof",
    "native_https_body_io_invalid_data",
    "native_https_body_io_invalid_input",
    "native_https_body_io_other",
    "native_https_body_io_reset",
    "native_https_body_parse_failed",
    "native_https_busy",
    "native_https_chunk_extensions_limit",
    "native_https_chunk_framing_invalid",
    "native_https_chunk_trailers_invalid",
    "native_https_failed",
    "native_https_incomplete_body",
    "native_https_tls_close_notify_missing",
    "stream_transport_unavailable",
];

/// Exact-match the native transport vocabulary for one message.
pub(crate) fn transport_category(message: &str) -> Option<&'static str> {
    NATIVE_TRANSPORT_CATEGORIES
        .iter()
        .copied()
        .find(|known| known == &message)
}

/// Bounded, resource-free diagnostic retained across the host boundary and the
/// durable `model.failed` publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransportFailureDetail {
    pub(crate) phase: &'static str,
    pub(crate) category: &'static str,
}

impl TransportFailureDetail {
    /// Classify a stream failure at its native owner, before it is flattened to
    /// a public code. Cancellation, deadline and revocation failures keep their
    /// own codes and publish no transport detail.
    pub(crate) fn classify(failure: &OAuthError, phase: &'static str) -> Option<Self> {
        match failure {
            OAuthError::Transport { message } => {
                transport_category(message).map(|category| Self { phase, category })
            }
            _ => None,
        }
    }

    /// Admit a phase/category pair decoded from dynamic provider JSON. Both
    /// members must match the fixed vocabulary exactly; a missing, unknown,
    /// mistyped or mismatched value omits the whole detail.
    pub(crate) fn admit(phase: &str, category: &str) -> Option<Self> {
        let phase = if phase == PHASE_START {
            PHASE_START
        } else if phase == PHASE_READ {
            PHASE_READ
        } else {
            return None;
        };
        transport_category(category).map(|category| Self { phase, category })
    }
}
