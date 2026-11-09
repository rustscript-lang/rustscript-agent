//! Plain-text Telegram presentation. Tool bursts share a progress bubble;
//! group replies edit real messages, private replies stream transient drafts.
//! Only acknowledged API operations become the next edit target.
use serde_json::Value;
use std::collections::VecDeque;

pub const TELEGRAM_MAX_UTF16: usize = 4096;

#[derive(Debug, Clone, PartialEq)]
pub enum RenderAction {
    Send { text: String },
    SendDelta { text: String },
    Edit { message_id: i64, text: String },
    Draft { text: String },
    Delete { message_id: i64 },
}

#[derive(Debug, Default)]
struct Bubble {
    text: String,
    delivered: Vec<(i64, String)>,
}

#[derive(Debug, Clone, Copy)]
enum Target {
    Progress,
    Body,
}

#[derive(Debug, Default)]
pub struct EventRenderer {
    progress: Bubble,
    body: Bubble,
    sends: VecDeque<(Target, String)>,
    private: bool,
    finished: bool,
    last_draft: String,
}

impl EventRenderer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn for_chat(chat_id: i64) -> Self {
        // Telegram private chat IDs are positive; group/channel IDs are negative.
        Self {
            private: chat_id > 0,
            ..Self::default()
        }
    }

    pub fn note_sent(&mut self, message_id: i64) {
        if let Some((target, text)) = self.sends.pop_front() {
            self.bubble(target).delivered.push((message_id, text));
        }
    }

    pub fn note_edited(&mut self, message_id: i64, text: &str) {
        for bubble in [&mut self.progress, &mut self.body] {
            if let Some((_, sent)) = bubble
                .delivered
                .iter_mut()
                .find(|(id, _)| *id == message_id)
            {
                *sent = text.to_string();
            }
        }
    }

    pub fn note_deleted(&mut self, message_id: i64) {
        for bubble in [&mut self.progress, &mut self.body] {
            bubble.delivered.retain(|(id, _)| *id != message_id);
        }
    }

    pub fn note_draft(&mut self, text: &str) {
        self.last_draft = text.to_string();
    }

    pub fn on_event(&mut self, event_type: &str, data: &Value) -> Vec<RenderAction> {
        if self.finished {
            return Vec::new();
        }
        match event_type {
            "model.delta" => self.body.text.push_str(&delta_text(data)),
            "message.delta" => self.body.text = delta_text(data),
            "tool.requested" => {
                // A tool call closes any preceding model commentary. The next
                // text turn starts a new body below this new progress burst.
                if !self.body.text.is_empty() {
                    self.body = Bubble::default();
                    self.progress = Bubble::default();
                    self.last_draft.clear();
                }
                self.status(&format!("[tool] {} requested", tool_name(data)));
            }
            "tool.completed" => self.status(&format!("[tool] {} completed", tool_name(data))),
            "tool.failed" => self.status(&format!("[tool] {} failed", tool_name(data))),
            "approval.required" => self.status(&format!(
                "[approval] {} requires approval (pending)",
                tool_name(data)
            )),
            "approval.resolved" => self.status(&format!(
                "[approval] {}: {}",
                tool_name(data),
                approval_state(data)
            )),
            "compact.started" => self.status("[compact] started"),
            "compact.completed" => self.status("[compact] completed"),
            "run.completed" => {
                if let Some(text) = data.pointer("/output/text").and_then(Value::as_str) {
                    self.body.text = text.to_string();
                } else if let Some(blocks) = data
                    .pointer("/output/message/content")
                    .and_then(Value::as_array)
                {
                    self.body.text = blocks
                        .iter()
                        .filter_map(|block| block.get("text").and_then(Value::as_str))
                        .collect();
                }
                self.finished = true;
            }
            "run.failed" | "run.cancelled" => {
                if self.private {
                    self.body.text.clear();
                }
                if event_type == "run.failed" {
                    self.status(&format!("[failed] {}", error_message(data)));
                } else {
                    self.status("[stopped]");
                }
                self.finished = true;
            }
            _ => return Vec::new(),
        }
        let mut actions = self.flush();
        if event_type == "run.completed" {
            actions.push(RenderAction::Send {
                text: "[done]".into(),
            });
        }
        actions
    }

    fn bubble(&mut self, target: Target) -> &mut Bubble {
        match target {
            Target::Progress => &mut self.progress,
            Target::Body => &mut self.body,
        }
    }

    fn status(&mut self, line: &str) {
        if !self.progress.text.is_empty() {
            self.progress.text.push('\n');
        }
        self.progress.text.push_str(line);
    }

    /// Re-plan unacknowledged snapshots. A throttled update remains dirty and
    /// is emitted by the driver's timer or forced terminal flush.
    pub fn flush(&mut self) -> Vec<RenderAction> {
        self.sends.clear();
        let mut actions = Vec::new();
        plan_bubble(
            &self.progress,
            Target::Progress,
            &mut self.sends,
            &mut actions,
        );
        if self.private && !self.finished {
            if !self.body.text.is_empty() {
                let preview = chunk_text(&self.body.text).remove(0);
                if preview != self.last_draft {
                    actions.push(RenderAction::Draft { text: preview });
                }
            }
        } else {
            plan_bubble(&self.body, Target::Body, &mut self.sends, &mut actions);
        }
        actions
    }
}

fn plan_bubble(
    bubble: &Bubble,
    target: Target,
    sends: &mut VecDeque<(Target, String)>,
    actions: &mut Vec<RenderAction>,
) {
    let chunks = if bubble.text.is_empty() {
        Vec::new()
    } else {
        chunk_text(&bubble.text)
    };
    for (index, text) in chunks.iter().enumerate() {
        if let Some((message_id, old)) = bubble.delivered.get(index) {
            if old != text {
                actions.push(RenderAction::Edit {
                    message_id: *message_id,
                    text: text.clone(),
                });
            }
        } else {
            sends.push_back((target, text.clone()));
            actions.push(match target {
                Target::Progress => RenderAction::Send { text: text.clone() },
                Target::Body => RenderAction::SendDelta { text: text.clone() },
            });
        }
    }
    for (message_id, _) in bubble.delivered.iter().skip(chunks.len()).rev() {
        actions.push(RenderAction::Delete {
            message_id: *message_id,
        });
    }
}

pub fn utf16_len(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

pub fn chunk_text(text: &str) -> Vec<String> {
    if utf16_len(text) <= TELEGRAM_MAX_UTF16 {
        return vec![text.to_string()];
    }
    let mut result = Vec::new();
    let mut current = String::new();
    let mut length = 0;
    for ch in text.chars() {
        if length + ch.len_utf16() > TELEGRAM_MAX_UTF16 {
            result.push(std::mem::take(&mut current));
            length = 0;
        }
        current.push(ch);
        length += ch.len_utf16();
    }
    if !current.is_empty() {
        result.push(current);
    }
    result
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

    fn acknowledge(renderer: &mut EventRenderer, actions: &[RenderAction]) {
        for (index, action) in actions.iter().enumerate() {
            match action {
                RenderAction::Send { .. } | RenderAction::SendDelta { .. } => {
                    renderer.note_sent(100 + index as i64)
                }
                RenderAction::Edit { message_id, text } => renderer.note_edited(*message_id, text),
                RenderAction::Draft { text } => renderer.note_draft(text),
                RenderAction::Delete { message_id } => renderer.note_deleted(*message_id),
            }
        }
    }

    fn final_actions(renderer: &mut EventRenderer, data: Value) -> Vec<RenderAction> {
        let mut actions = renderer.on_event("run.completed", &data);
        assert_eq!(
            actions.pop(),
            Some(RenderAction::Send {
                text: "[done]".into()
            })
        );
        actions
    }

    #[test]
    fn terminal_message_restores_authoritative_text_without_prior_preview() {
        let mut renderer = EventRenderer::for_chat(555);
        assert_eq!(
            final_actions(
                &mut renderer,
                json!({"output":{"message":{"content":[{"type":"text","text":"restored answer"}]}}})
            ),
            vec![RenderAction::SendDelta {
                text: "restored answer".into()
            }]
        );
    }

    #[test]
    fn consecutive_tool_events_edit_the_same_progress_message() {
        let mut renderer = EventRenderer::new();
        assert_eq!(
            renderer
                .on_event("tool.requested", &json!({"name":"read_file"}))
                .len(),
            1
        );
        renderer.note_sent(41);
        assert_eq!(
            renderer.on_event("tool.completed", &json!({"name":"read_file"})),
            vec![RenderAction::Edit {
                message_id: 41,
                text: "[tool] read_file requested\n[tool] read_file completed".into()
            }]
        );
    }
    #[test]
    fn authoritative_terminal_text_replaces_streamed_preview() {
        let mut renderer = EventRenderer::new();
        renderer.on_event("model.delta", &json!({"delta":"preview"}));
        renderer.note_sent(42);
        assert_eq!(
            final_actions(&mut renderer, json!({"output":{"text":"final answer"}})),
            vec![RenderAction::Edit {
                message_id: 42,
                text: "final answer".into()
            }]
        );
    }
    #[test]
    fn private_chat_uses_draft_then_one_committed_final() {
        let mut renderer = EventRenderer::for_chat(42);
        let actions = renderer.on_event("model.delta", &json!({"delta":"Hel"}));
        assert_eq!(actions, vec![RenderAction::Draft { text: "Hel".into() }]);
        acknowledge(&mut renderer, &actions);
        assert!(renderer.flush().is_empty());
        assert_eq!(
            renderer.on_event("model.delta", &json!({"delta":"lo"})),
            vec![RenderAction::Draft {
                text: "Hello".into()
            }]
        );
        let actions = final_actions(&mut renderer, json!({"output":{"text":"Hello"}}));
        assert_eq!(
            actions,
            vec![RenderAction::SendDelta {
                text: "Hello".into()
            }]
        );
        acknowledge(&mut renderer, &actions);
        assert!(renderer.flush().is_empty());
    }
    #[test]
    fn group_chat_edits_preview_in_place() {
        let mut renderer = EventRenderer::for_chat(-10042);
        let actions = renderer.on_event("model.delta", &json!({"delta":"Hel"}));
        assert_eq!(
            actions,
            vec![RenderAction::SendDelta { text: "Hel".into() }]
        );
        renderer.note_sent(12);
        assert_eq!(
            renderer.on_event("model.delta", &json!({"delta":"lo"})),
            vec![RenderAction::Edit {
                message_id: 12,
                text: "Hello".into()
            }]
        );
    }
    #[test]
    fn throttled_edit_remains_available_until_acknowledged() {
        let mut renderer = EventRenderer::new();
        renderer.on_event("model.delta", &json!({"delta":"a"}));
        renderer.note_sent(4);
        let pending = renderer.on_event("model.delta", &json!({"delta":"b"}));
        assert_eq!(renderer.flush(), pending);
        acknowledge(&mut renderer, &pending);
        assert!(renderer.flush().is_empty());
    }
    #[test]
    fn progress_and_body_have_separate_edit_targets() {
        let mut renderer = EventRenderer::new();
        renderer.on_event("tool.requested", &json!({"name":"terminal"}));
        renderer.note_sent(1);
        renderer.on_event("model.delta", &json!({"delta":"answer"}));
        renderer.note_sent(2);
        let actions = final_actions(&mut renderer, json!({"output":{"text":"final"}}));
        assert_eq!(
            actions,
            vec![RenderAction::Edit {
                message_id: 2,
                text: "final".into()
            }]
        );
    }
    #[test]
    fn buffered_final_is_committed_once_with_terminal_status() {
        let mut renderer = EventRenderer::new();
        let actions = final_actions(&mut renderer, json!({"output":{"text":"buffered"}}));
        assert_eq!(
            actions,
            vec![RenderAction::SendDelta {
                text: "buffered".into()
            }]
        );
        acknowledge(&mut renderer, &actions);
        assert!(renderer.flush().is_empty());
    }
    #[test]
    fn utf16_chunks_preserve_unicode_and_overflow_target_ids() {
        let text = "a".repeat(4095) + "\u{1f642}" + "tail";
        let chunks = chunk_text(&text);
        assert_eq!(chunks.concat(), text);
        assert!(chunks.iter().all(|x| utf16_len(x) <= TELEGRAM_MAX_UTF16));
        let mut renderer = EventRenderer::new();
        let actions = renderer.on_event("model.delta", &json!({"delta":text}));
        acknowledge(&mut renderer, &actions);
        assert_eq!(
            renderer.on_event("model.delta", &json!({"delta":"!"})),
            vec![RenderAction::Edit {
                message_id: 101,
                text: "\u{1f642}tail!".into()
            }]
        );
    }
    #[test]
    fn final_shortening_removes_surplus_preview_chunks() {
        let mut renderer = EventRenderer::new();
        let actions = renderer.on_event("model.delta", &json!({"delta":"x".repeat(4097)}));
        acknowledge(&mut renderer, &actions);
        let actions = final_actions(&mut renderer, json!({"output":{"text":"short"}}));
        assert_eq!(
            actions,
            vec![
                RenderAction::Edit {
                    message_id: 100,
                    text: "short".into()
                },
                RenderAction::Delete { message_id: 101 }
            ]
        );
        acknowledge(&mut renderer, &actions);
        assert!(renderer.flush().is_empty());
    }
    #[test]
    fn tool_call_starts_a_new_turn_below_prior_commentary() {
        let mut renderer = EventRenderer::new();
        renderer.on_event("model.delta", &json!({"delta":"checking"}));
        renderer.note_sent(7);
        let actions = renderer.on_event("tool.requested", &json!({"name":"read_file"}));
        acknowledge(&mut renderer, &actions);
        assert!(matches!(
            renderer
                .on_event("model.delta", &json!({"delta":"answer"}))
                .last(),
            Some(RenderAction::SendDelta { .. })
        ));
    }
    #[test]
    fn failure_and_cancellation_finalize_progress_without_committing_private_partial_text() {
        for event in ["run.failed", "run.cancelled"] {
            let mut renderer = EventRenderer::for_chat(42);
            renderer.on_event("model.delta", &json!({"delta":"partial"}));
            let actions = renderer.on_event(event, &json!({"error_message":"failed"}));
            assert!(
                actions
                    .iter()
                    .all(|a| matches!(a, RenderAction::Send { .. }))
            );
            acknowledge(&mut renderer, &actions);
            assert!(renderer.flush().is_empty());
        }
    }
}
