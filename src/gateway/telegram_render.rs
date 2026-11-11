//! Plain-text Telegram presentation. Tool bursts share a progress bubble;
//! group replies edit real messages, private replies stream transient drafts.
//! Only acknowledged API operations become the next edit target.
use super::telegram_format::paired_markdown_chunks;
use serde_json::Value;
use std::collections::VecDeque;

pub const TELEGRAM_MAX_UTF16: usize = 4096;

#[derive(Debug, Clone, PartialEq)]
pub enum RenderAction {
    Send {
        text: String,
    },
    SendDelta {
        text: String,
    },
    /// Finished private/new body. `text` is MarkdownV2; `plain` is the fallback.
    SendFinal {
        text: String,
        plain: String,
    },
    Edit {
        message_id: i64,
        text: String,
    },
    /// Finished group/topic body edit, even when the raw text is unchanged.
    EditFinal {
        message_id: i64,
        text: String,
        plain: String,
    },
    Draft {
        text: String,
    },
    Delete {
        message_id: i64,
    },
}

#[derive(Debug, Default)]
struct Bubble {
    text: String,
    delivered: Vec<(i64, String)>,
    /// Parallel to `delivered`. True only after a successful final ACK.
    final_slots: Vec<bool>,
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
    sends: VecDeque<(Target, String, bool)>,
    private: bool,
    finished: bool,
    markdown_final: bool,
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
        if let Some((target, text, finalize)) = self.sends.pop_front() {
            self.record_sent(target, message_id, text, finalize);
        }
    }

    /// Records a successful send whose wire text differs from the queued plan,
    /// such as a one-shot plain fallback after a Markdown parse error.
    pub fn note_sent_text(&mut self, message_id: i64, text: &str) {
        if let Some((target, _, finalize)) = self.sends.pop_front() {
            self.record_sent(target, message_id, text.to_string(), finalize);
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

    pub fn note_body_final_edit(&mut self, message_id: i64, text: &str) {
        self.note_edited(message_id, text);
        if let Some(index) = self
            .body
            .delivered
            .iter()
            .position(|(id, _)| *id == message_id)
        {
            if self.body.final_slots.len() <= index {
                self.body.final_slots.resize(index + 1, false);
            }
            self.body.final_slots[index] = true;
        }
    }

    pub fn note_deleted(&mut self, message_id: i64) {
        for bubble in [&mut self.progress, &mut self.body] {
            if let Some(index) = bubble
                .delivered
                .iter()
                .position(|(id, _)| *id == message_id)
            {
                bubble.delivered.remove(index);
                if index < bubble.final_slots.len() {
                    bubble.final_slots.remove(index);
                }
            }
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
                self.markdown_final = true;
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

    fn record_sent(&mut self, target: Target, message_id: i64, text: String, finalize: bool) {
        let bubble = self.bubble(target);
        bubble.delivered.push((message_id, text));
        bubble.final_slots.push(finalize);
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
        } else if self.markdown_final {
            plan_final_body(&self.body, &mut self.sends, &mut actions);
        } else {
            plan_bubble(&self.body, Target::Body, &mut self.sends, &mut actions);
        }
        actions
    }
}

fn plan_bubble(
    bubble: &Bubble,
    target: Target,
    sends: &mut VecDeque<(Target, String, bool)>,
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
            sends.push_back((target, text.clone(), false));
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

fn plan_final_body(
    bubble: &Bubble,
    sends: &mut VecDeque<(Target, String, bool)>,
    actions: &mut Vec<RenderAction>,
) {
    if bubble.text.is_empty() {
        for (message_id, _) in bubble.delivered.iter().rev() {
            actions.push(RenderAction::Delete {
                message_id: *message_id,
            });
        }
        return;
    }
    let pairs = paired_markdown_chunks(&bubble.text);
    for (index, (text, fallback)) in pairs.iter().enumerate() {
        if let Some((message_id, _)) = bubble.delivered.get(index) {
            let finalized = bubble.final_slots.get(index).copied().unwrap_or(false);
            if !finalized {
                actions.push(RenderAction::EditFinal {
                    message_id: *message_id,
                    text: text.clone(),
                    plain: fallback.to_string(),
                });
            }
        } else {
            sends.push_back((Target::Body, text.clone(), true));
            actions.push(RenderAction::SendFinal {
                text: text.clone(),
                plain: fallback.to_string(),
            });
        }
    }
    for (message_id, _) in bubble.delivered.iter().skip(pairs.len()).rev() {
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
                RenderAction::Send { .. }
                | RenderAction::SendDelta { .. }
                | RenderAction::SendFinal { .. } => renderer.note_sent(100 + index as i64),
                RenderAction::Edit { message_id, text } => renderer.note_edited(*message_id, text),
                RenderAction::EditFinal {
                    message_id, text, ..
                } => renderer.note_body_final_edit(*message_id, text),
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
    fn unchanged_group_preview_still_requests_a_terminal_edit() {
        let mut renderer = EventRenderer::for_chat(-1001);
        let actions = renderer.on_event("model.delta", &json!({"delta": "Hello"}));
        acknowledge(&mut renderer, &actions);
        let actions = renderer.on_event("run.completed", &json!({"output":{"text":"Hello"}}));
        assert!(
            actions.iter().any(|action| matches!(
                action,
                RenderAction::EditFinal {
                    message_id: 100,
                    text,
                    ..
                } if text == "Hello"
            )),
            "identical raw final must still edit the preview, got {actions:?}"
        );
        assert!(actions.iter().any(|action| matches!(
            action,
            RenderAction::Send { text } if text == "[done]"
        )));
        acknowledge(&mut renderer, &actions);
        assert!(renderer.flush().is_empty());
    }

    #[test]
    fn terminal_message_restores_authoritative_text_without_prior_preview() {
        let mut renderer = EventRenderer::for_chat(555);
        assert_eq!(
            final_actions(
                &mut renderer,
                json!({"output":{"message":{"content":[{"type":"text","text":"restored answer"}]}}})
            ),
            vec![RenderAction::SendFinal {
                text: "restored answer".into(),
                plain: "restored answer".into()
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
            vec![RenderAction::EditFinal {
                message_id: 42,
                text: "final answer".into(),
                plain: "final answer".into()
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
            vec![RenderAction::SendFinal {
                text: "Hello".into(),
                plain: "Hello".into()
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
            vec![RenderAction::EditFinal {
                message_id: 2,
                text: "final".into(),
                plain: "final".into()
            }]
        );
    }
    #[test]
    fn buffered_final_is_committed_once_with_terminal_status() {
        let mut renderer = EventRenderer::new();
        let actions = final_actions(&mut renderer, json!({"output":{"text":"buffered"}}));
        assert_eq!(
            actions,
            vec![RenderAction::SendFinal {
                text: "buffered".into(),
                plain: "buffered".into()
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
                RenderAction::EditFinal {
                    message_id: 100,
                    text: "short".into(),
                    plain: "short".into()
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

    #[test]
    fn private_final_sends_and_group_or_topic_final_edits() {
        let mut private = EventRenderer::for_chat(7);
        let actions = final_actions(&mut private, json!({"output":{"text":"Hi"}}));
        assert!(matches!(
            actions.as_slice(),
            [RenderAction::SendFinal { .. }]
        ));
        for chat_id in [-100_i64, -1001234] {
            let mut group = EventRenderer::for_chat(chat_id);
            let preview = group.on_event("model.delta", &json!({"delta":"Hi"}));
            acknowledge(&mut group, &preview);
            let actions = final_actions(&mut group, json!({"output":{"text":"Hi"}}));
            assert!(matches!(
                actions.as_slice(),
                [RenderAction::EditFinal {
                    message_id: 100,
                    ..
                }]
            ));
        }
    }

    #[test]
    fn both_terminal_shapes_format_markdown_and_leave_done_plain() {
        for data in [
            json!({"output":{"text":"**done**"}}),
            json!({"output":{"message":{"content":[{"type":"text","text":"**done**"}]}}}),
        ] {
            let mut renderer = EventRenderer::for_chat(-100);
            let preview = renderer.on_event("model.delta", &json!({"delta":"**done**"}));
            acknowledge(&mut renderer, &preview);
            let actions = renderer.on_event("run.completed", &data);
            assert!(actions.iter().any(|action| matches!(
                action,
                RenderAction::EditFinal { message_id: 100, text, .. } if text == "*done*"
            )));
            assert!(actions.iter().any(|action| matches!(
                action,
                RenderAction::Send { text } if text == "[done]"
            )));
            assert!(!actions.iter().any(|action| matches!(
                action,
                RenderAction::SendFinal { text, .. } if text == "[done]"
            )));
        }
    }

    #[test]
    fn final_escapes_specials_and_keeps_code_fences_inside_utf16() {
        let mut renderer = EventRenderer::for_chat(-1);
        let preview = renderer.on_event("model.delta", &json!({"delta":"a_b"}));
        acknowledge(&mut renderer, &preview);
        let actions = final_actions(&mut renderer, json!({"output":{"text":"a_b!"}}));
        assert!(matches!(
            &actions[0],
            RenderAction::EditFinal { text, .. } if text == "a\\_b\\!"
        ));
        let mut long = EventRenderer::for_chat(9);
        let body = format!("```\n{}\n```", "x".repeat(5000));
        let actions = final_actions(&mut long, json!({"output":{"text": body}}));
        assert!(actions.iter().all(|action| match action {
            RenderAction::SendFinal { text, .. } => utf16_len(text) <= TELEGRAM_MAX_UTF16,
            _ => false,
        }));
        assert!(actions.len() > 1);
    }

    /// Business regression: a long fence is formatted once, then split so each
    /// code character appears once and each plain fallback is that chunk's
    /// source slice. The oracle does not call the production formatter.
    #[test]
    fn long_fenced_final_keeps_code_once_and_pairs_each_source_slice() {
        let code = "x".repeat(5000);
        let source = format!("```\n{code}\n```");
        let mut renderer = EventRenderer::for_chat(9);
        let actions = final_actions(&mut renderer, json!({"output":{"text": source}}));
        let mut recovered = String::new();
        let mut plains = String::new();
        assert!(
            actions.len() > 1,
            "5000-char fence must span more than one final"
        );
        for action in &actions {
            let RenderAction::SendFinal { text, plain } = action else {
                panic!("private long fence must send finals, got {action:?}");
            };
            assert!(
                utf16_len(text) <= TELEGRAM_MAX_UTF16,
                "formatted chunk is {} UTF-16 units",
                utf16_len(text)
            );
            assert!(
                utf16_len(plain) <= TELEGRAM_MAX_UTF16,
                "plain fallback is {} UTF-16 units",
                utf16_len(plain)
            );
            let body = closed_fence_body(text);
            assert!(
                body.chars().all(|ch| ch == 'x'),
                "fence body was escaped or split as prose: {}",
                text.chars().take(48).collect::<String>()
            );
            recovered.push_str(body);
            plains.push_str(plain);
        }
        assert_eq!(recovered, code, "code characters must appear exactly once");
        assert_eq!(
            plains, source,
            "plain slices must restore the original source exactly once"
        );
    }

    /// Escape expansion must not split a backslash from its character, and each
    /// plain slice is only the source covered by that chunk.
    #[test]
    fn escape_heavy_final_keeps_pairs_and_source_slices() {
        let source = format!("a{}", "!".repeat(2500));
        let mut renderer = EventRenderer::for_chat(9);
        let actions = final_actions(&mut renderer, json!({"output":{"text": source}}));
        let mut visible = String::new();
        let mut plains = String::new();
        assert!(
            actions.len() > 1,
            "escaped prose must span more than one final"
        );
        for action in &actions {
            let RenderAction::SendFinal { text, plain } = action else {
                panic!("private escape-heavy final must send, got {action:?}");
            };
            assert!(utf16_len(text) <= TELEGRAM_MAX_UTF16);
            assert!(utf16_len(plain) <= TELEGRAM_MAX_UTF16);
            visible.push_str(&unescape_markdown_v2(text));
            plains.push_str(plain);
        }
        assert_eq!(
            visible, source,
            "escaped characters must appear exactly once"
        );
        assert_eq!(
            plains, source,
            "plain slices must restore the source exactly once"
        );
    }

    /// A short entity inside escape-expanded prose must stay one closed unit.
    /// The expected bold form is the Telegram mapping, not a call to the formatter.
    #[test]
    fn mixed_plain_and_bold_keeps_entity_and_source_once() {
        let bangs = "!".repeat(2100);
        let source = format!("{bangs}**keep me**{bangs}");
        let mut renderer = EventRenderer::for_chat(9);
        let actions = final_actions(&mut renderer, json!({"output":{"text": source}}));
        let mut plains = String::new();
        let mut visible = String::new();
        let mut entity_hits = 0usize;
        assert!(
            actions.len() > 1,
            "mixed body must span more than one final"
        );
        for action in &actions {
            let RenderAction::SendFinal { text, plain } = action else {
                panic!("private mixed final must send, got {action:?}");
            };
            assert!(utf16_len(text) <= TELEGRAM_MAX_UTF16);
            assert!(utf16_len(plain) <= TELEGRAM_MAX_UTF16);
            assert!(
                !text.contains("\\*\\*"),
                "bold markers must stay an entity, not escaped prose"
            );
            entity_hits += text.matches("*keep me*").count();
            plains.push_str(plain);
            visible.push_str(&recover_mixed_visible(text));
        }
        assert_eq!(
            entity_hits, 1,
            "bold entity must appear once and not be split"
        );
        assert_eq!(plains, source);
        assert_eq!(visible, format!("{bangs}keep me{bangs}"));
    }

    /// An emoji is one scalar and two UTF-16 units. It must not be split on a
    /// fence budget boundary, and the recovered fence body must match the source.
    #[test]
    fn utf16_boundary_emoji_stays_one_scalar_in_fence_and_source() {
        let emoji = "\u{1F600}";
        let code = format!("{}{emoji}{}", "x".repeat(4087), "y".repeat(40));
        let source = format!("```\n{code}\n```");
        let mut renderer = EventRenderer::for_chat(9);
        let actions = final_actions(&mut renderer, json!({"output":{"text": source}}));
        let mut recovered = String::new();
        let mut plains = String::new();
        assert!(
            actions.len() > 1,
            "emoji at the fence budget must force a second chunk"
        );
        for action in &actions {
            let RenderAction::SendFinal { text, plain } = action else {
                panic!("private utf16 final must send, got {action:?}");
            };
            assert!(utf16_len(text) <= TELEGRAM_MAX_UTF16);
            assert!(utf16_len(plain) <= TELEGRAM_MAX_UTF16);
            recovered.push_str(closed_fence_body(text));
            plains.push_str(plain);
        }
        assert_eq!(recovered.matches(emoji).count(), 1);
        assert_eq!(plains.matches(emoji).count(), 1);
        assert_eq!(recovered, code);
        assert_eq!(plains, source);
    }

    fn recover_mixed_visible(text: &str) -> String {
        let stripped = text.replace("*keep me*", "keep me");
        unescape_markdown_v2(&stripped)
    }

    fn unescape_markdown_v2(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                let escaped = chars
                    .next()
                    .unwrap_or_else(|| panic!("dangling escape in {text:?}"));
                out.push(escaped);
            } else {
                out.push(ch);
            }
        }
        out
    }

    fn closed_fence_body(chunk: &str) -> &str {
        let rest = chunk
            .strip_prefix("```")
            .unwrap_or_else(|| panic!("chunk does not open a fence: {chunk:?}"));
        let body = if let Some(stripped) = rest.strip_prefix('\n') {
            stripped
        } else {
            let newline = rest
                .find('\n')
                .unwrap_or_else(|| panic!("fence header has no newline: {chunk:?}"));
            &rest[newline + 1..]
        };
        body.strip_suffix("\n```")
            .unwrap_or_else(|| panic!("chunk does not close its fence: {chunk:?}"))
    }
}
