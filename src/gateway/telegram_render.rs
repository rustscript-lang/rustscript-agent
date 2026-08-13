//! Canonical agent events → Telegram text rendering.
//!
//! Rendering strategy: plain text. No Markdown/HTML `parse_mode` is used —
//! Telegram's parse modes require escaping, change the effective length
//! budget, and can turn user content into markup errors. Plain text is
//! UTF-8 safe end to end and the only constraint is Telegram's 4096-UTF-16-
//! code-unit message cap.
//!
//! [`chunk_text`] counts UTF-16 code units (Telegram's own length metric)
//! and never splits a Unicode scalar value. [`EventRenderer`] turns one
//! canonical event into a bounded list of `Send`/`Edit` actions: `model.delta`
//! streams into one message via `editMessageText` (the caller throttles
//! edits by [`crate::config::TelegramConfig::max_edit_interval`]; dropped
//! edits are harmless because the accumulated text is always re-sent in
//! full), and status lines (`tool.*`, `approval.*`, `compact.*`, terminal
//! runs) become separate plain-text messages. Approval events are rendered
//! as canonical event text only — no resolution semantics exist here.

use serde_json::Value;

/// Telegram's plain-text message cap in UTF-16 code units.
pub const TELEGRAM_MAX_UTF16: usize = 4096;

/// One bounded output action for the Bot API.
#[derive(Debug, Clone, PartialEq)]
pub enum RenderAction {
    /// A status line (tool/approval/terminal/compact); its reply id is
    /// never reported as the delta edit target.
    Send {
        text: String,
    },
    /// A delta-owned chunk; the driver reports its reply id via
    /// [`EventRenderer::note_sent`], making it the delta edit target.
    SendDelta {
        text: String,
    },
    Edit {
        message_id: i64,
        text: String,
    },
}

/// Pure per-run render state: the message being delta-edited and the
/// accumulated text. No I/O; the driver task owns the API calls.
#[derive(Debug, Default)]
pub struct EventRenderer {
    current_message_id: Option<i64>,
    current_text: String,
}

impl EventRenderer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reports the message id returned by a `sendMessage`; the last send in
    /// an action batch becomes the new edit target.
    pub fn note_sent(&mut self, message_id: i64) {
        self.current_message_id = Some(message_id);
    }

    /// Renders one canonical event into bounded actions.
    pub fn on_event(&mut self, event_type: &str, data: &Value) -> Vec<RenderAction> {
        match event_type {
            "model.delta" => self.on_delta(delta_text(data)),
            "message.delta" => {
                // The service-owned terminal message is the authoritative
                // final assistant text; it replaces any accumulated deltas.
                let delta = delta_text(data);
                if !delta.is_empty() {
                    self.current_text = delta;
                }
                self.flush()
            }
            "tool.requested" => send_line(&format!("[tool] {} requested", tool_name(data))),
            "tool.completed" => send_line(&format!("[tool] {} completed", tool_name(data))),
            "approval.required" => send_line(&format!(
                "[approval] {} requires approval (pending)",
                tool_name(data)
            )),
            "approval.resolved" => send_line(&format!(
                "[approval] {}: {}",
                tool_name(data),
                approval_state(data)
            )),
            "compact.started" => send_line("[compact] started"),
            "compact.completed" => send_line("[compact] completed"),
            "run.completed" => send_line("[done]"),
            "run.failed" => send_line(&format!("[failed] {}", error_message(data))),
            "run.cancelled" => send_line("[stopped]"),
            // run.started, model.started, model.completed, tool.started,
            // tool.output, subagent.*, and unknown events render nothing.
            _ => Vec::new(),
        }
    }

    /// Final edit/send of any accumulated delta text; called after the
    /// terminal event so the last edit is never dropped by throttling.
    pub fn flush(&mut self) -> Vec<RenderAction> {
        if self.current_text.is_empty() {
            return Vec::new();
        }
        let text = std::mem::take(&mut self.current_text);
        let chunks = chunk_text(&text);
        let mut actions = Vec::new();
        if let Some(message_id) = self.current_message_id {
            actions.push(RenderAction::Edit {
                message_id,
                text: chunks[0].clone(),
            });
            for chunk in &chunks[1..] {
                actions.push(RenderAction::SendDelta {
                    text: chunk.clone(),
                });
            }
        } else {
            for chunk in chunks {
                actions.push(RenderAction::SendDelta { text: chunk });
            }
        }
        actions
    }

    /// Appends one delta and returns the full accumulated text as an edit of
    /// the current message (or a delta send when no message exists yet).
    /// When the accumulated text crosses the cap, the overflow becomes fresh
    /// delta messages and the last chunk becomes the new edit target.
    fn on_delta(&mut self, delta: String) -> Vec<RenderAction> {
        if delta.is_empty() {
            return Vec::new();
        }
        self.current_text.push_str(&delta);
        let chunks = chunk_text(&self.current_text);
        let mut actions = Vec::new();
        if let Some(message_id) = self.current_message_id {
            actions.push(RenderAction::Edit {
                message_id,
                text: chunks[0].clone(),
            });
            for chunk in &chunks[1..] {
                actions.push(RenderAction::SendDelta {
                    text: chunk.clone(),
                });
            }
        } else {
            for chunk in &chunks {
                actions.push(RenderAction::SendDelta {
                    text: chunk.clone(),
                });
            }
        }
        self.current_text = chunks[chunks.len() - 1].clone();
        if self.current_message_id.is_none() {
            // The driver reports the last delta send's id via note_sent;
            // that message becomes the new edit target.
            self.current_message_id = None;
        }
        actions
    }
}

/// Length of `text` in UTF-16 code units (Telegram's message-length metric).
pub fn utf16_len(text: &str) -> usize {
    text.chars().map(|ch| ch.len_utf16()).sum()
}

/// Splits `text` into chunks of at most [`TELEGRAM_MAX_UTF16`] UTF-16 code
/// units, never splitting a Unicode scalar value.
pub fn chunk_text(text: &str) -> Vec<String> {
    if utf16_len(text) <= TELEGRAM_MAX_UTF16 {
        return vec![text.to_string()];
    }
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut current_len = 0usize;
    for ch in text.chars() {
        let ch_len = ch.len_utf16();
        if current_len + ch_len > TELEGRAM_MAX_UTF16 && !current.is_empty() {
            chunks.push(std::mem::take(&mut current));
            current_len = 0;
        }
        current.push(ch);
        current_len += ch_len;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// Renders one status line as chunked sends (a pathological oversized name
/// still stays within the message cap).
fn send_line(text: &str) -> Vec<RenderAction> {
    chunk_text(text)
        .into_iter()
        .map(|text| RenderAction::Send { text })
        .collect()
}

fn delta_text(data: &Value) -> String {
    data.get("delta")
        .or_else(|| data.get("text"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn tool_name(data: &Value) -> String {
    data.get("tool_call")
        .and_then(|call| call.get("name"))
        .or_else(|| data.get("tool_name"))
        .or_else(|| data.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("unknown tool")
        .to_string()
}

fn approval_state(data: &Value) -> String {
    data.get("state")
        .or_else(|| data.get("decision"))
        .and_then(Value::as_str)
        .unwrap_or("resolved")
        .to_string()
}

fn error_message(data: &Value) -> String {
    data.get("error_message")
        .or_else(|| data.get("message"))
        .or_else(|| data.get("error"))
        .or_else(|| data.get("error_code"))
        .or_else(|| data.get("recovery_reason"))
        .and_then(Value::as_str)
        .unwrap_or("run failed")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn utf16_len_counts_code_units_not_chars() {
        assert_eq!(utf16_len("abc"), 3);
        // CJK characters are 1 UTF-16 unit; emoji are 2.
        assert_eq!(utf16_len("中文"), 2);
        assert_eq!(utf16_len("a😀"), 3);
    }

    #[test]
    fn chunk_text_never_splits_scalars_and_respects_the_cap() {
        let text = "a".repeat(4096) + "😀" + &"b".repeat(100);
        let chunks = chunk_text(&text);
        assert!(chunks.len() >= 2, "oversized text must be chunked");
        for chunk in &chunks {
            assert!(
                utf16_len(chunk) <= TELEGRAM_MAX_UTF16,
                "chunk {chunk:?} exceeds the Telegram cap"
            );
        }
        assert_eq!(chunks[0], "a".repeat(4096));
        assert_eq!(chunks[1].chars().next(), Some('😀'), "emoji must not split");
        assert_eq!(chunks.concat(), text, "chunking must be lossless");
        assert_eq!(chunk_text("short"), vec!["short".to_string()]);
    }

    #[test]
    fn deltas_edit_one_message_and_the_terminal_flush_finalizes() {
        let mut renderer = EventRenderer::new();
        let actions = renderer.on_event("model.delta", &json!({"delta": "Hel"}));
        assert_eq!(
            actions,
            vec![RenderAction::SendDelta {
                text: "Hel".to_string()
            }],
            "the first delta sends the opening message"
        );
        renderer.note_sent(41);
        let actions = renderer.on_event("model.delta", &json!({"delta": "lo"}));
        assert_eq!(
            actions,
            vec![RenderAction::Edit {
                message_id: 41,
                text: "Hello".to_string()
            }],
            "later deltas edit the same message"
        );
        let actions = renderer.on_event("message.delta", &json!({"delta": "final"}));
        assert_eq!(
            actions,
            vec![RenderAction::Edit {
                message_id: 41,
                text: "final".to_string()
            }],
            "the terminal message delta replaces the deltas with the final text"
        );
        assert_eq!(renderer.flush(), Vec::new(), "nothing left to flush");
    }

    #[test]
    fn overflow_delta_splits_into_fresh_messages() {
        let mut renderer = EventRenderer::new();
        let big = "x".repeat(4096) + "y";
        let actions = renderer.on_event("model.delta", &json!({"delta": big}));
        assert_eq!(actions.len(), 2, "one send for the head, one for the tail");
        match &actions[0] {
            RenderAction::SendDelta { text } => assert_eq!(text.len(), 4096),
            other => panic!("expected a delta send for the first chunk: {other:?}"),
        }
        match &actions[1] {
            RenderAction::SendDelta { text } => assert_eq!(text, "y"),
            other => panic!("expected a delta send for the overflow: {other:?}"),
        }
        // The last send becomes the new edit target.
        renderer.note_sent(7);
        let actions = renderer.on_event("model.delta", &json!({"delta": "z"}));
        assert_eq!(
            actions,
            vec![RenderAction::Edit {
                message_id: 7,
                text: "yz".to_string()
            }]
        );
    }

    #[test]
    fn status_lines_render_as_separate_messages() {
        let mut renderer = EventRenderer::new();
        let events = vec![
            (
                "tool.requested",
                json!({"tool_call": {"id": "t1", "name": "web_search"}}),
                "[tool] web_search requested",
            ),
            (
                "tool.completed",
                json!({"tool_call": {"id": "t1", "name": "web_search"}}),
                "[tool] web_search completed",
            ),
            (
                "approval.required",
                json!({"tool_call": {"id": "t1", "name": "web_search"}, "approval_id": "a1"}),
                "[approval] web_search requires approval (pending)",
            ),
            (
                "approval.resolved",
                json!({"tool_call": {"id": "t1", "name": "web_search"}, "state": "approved"}),
                "[approval] web_search: approved",
            ),
            ("compact.started", json!({}), "[compact] started"),
            ("compact.completed", json!({}), "[compact] completed"),
            ("run.completed", json!({"status": "completed"}), "[done]"),
            (
                "run.failed",
                json!({"error_message": "boom"}),
                "[failed] boom",
            ),
            ("run.cancelled", json!({"status": "cancelled"}), "[stopped]"),
        ];
        for (event_type, data, expected) in events {
            let actions = renderer.on_event(event_type, &data);
            assert_eq!(
                actions,
                vec![RenderAction::Send {
                    text: expected.to_string()
                }],
                "{event_type} must render its status line"
            );
        }
    }

    #[test]
    fn non_rendered_events_produce_no_actions() {
        let mut renderer = EventRenderer::new();
        for (event_type, data) in [
            ("run.started", json!({"status": "running"})),
            ("model.started", json!({"model": "local"})),
            ("model.completed", json!({"model": "local"})),
            ("tool.started", json!({"tool_call": {"name": "x"}})),
            ("tool.output", json!({"output": "..."})),
            ("subagent.started", json!({})),
            ("subagent.completed", json!({})),
            ("not_a_canonical_event", json!({})),
        ] {
            assert_eq!(
                renderer.on_event(event_type, &data),
                Vec::new(),
                "{event_type} must render nothing"
            );
        }
        // Terminal lines must not disturb an in-flight delta stream.
        let actions = renderer.on_event("model.delta", &json!({"delta": "a"}));
        assert_eq!(actions.len(), 1);
        renderer.note_sent(9);
        let _ = renderer.on_event("run.completed", &json!({}));
        let actions = renderer.on_event("model.delta", &json!({"delta": "b"}));
        assert_eq!(
            actions,
            vec![RenderAction::Edit {
                message_id: 9,
                text: "ab".to_string()
            }]
        );
    }

    #[test]
    fn status_sends_never_claim_the_delta_edit_target() {
        // The delta edit target is tracked independently: a status line
        // between deltas renders as a plain send and must never become the
        // target of the next delta edit (the driver only reports delta
        // sends via note_sent).
        let mut renderer = EventRenderer::new();
        let actions = renderer.on_event("model.delta", &json!({"delta": "Hel"}));
        assert_eq!(
            actions,
            vec![RenderAction::SendDelta {
                text: "Hel".to_string()
            }],
            "the first delta opens a message owned by the delta stream"
        );
        renderer.note_sent(41);
        for (event_type, data, expected) in [
            (
                "tool.requested",
                json!({"tool_call": {"id": "t1", "name": "web_search"}}),
                "[tool] web_search requested",
            ),
            (
                "approval.resolved",
                json!({"tool_call": {"id": "t1", "name": "web_search"}, "state": "approved"}),
                "[approval] web_search: approved",
            ),
            ("run.completed", json!({"status": "completed"}), "[done]"),
        ] {
            let actions = renderer.on_event(event_type, &data);
            assert_eq!(
                actions,
                vec![RenderAction::Send {
                    text: expected.to_string()
                }],
                "{event_type} must render a plain status send"
            );
        }
        let actions = renderer.on_event("model.delta", &json!({"delta": "lo"}));
        assert_eq!(
            actions,
            vec![RenderAction::Edit {
                message_id: 41,
                text: "Hello".to_string()
            }],
            "the delta stream keeps editing its own message, not a status line"
        );
        // The terminal flush still finalizes the delta message.
        let actions = renderer.on_event("message.delta", &json!({"delta": "final"}));
        assert_eq!(
            actions,
            vec![RenderAction::Edit {
                message_id: 41,
                text: "final".to_string()
            }]
        );
    }
}
