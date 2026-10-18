//! Bounded native queue for capability-derived public OAuth instructions.

use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};

const AUTHORIZATION_INSTRUCTION_QUEUE_CAPACITY: usize = 4;

/// Public authorization URLs captured from an admitted native PKCE begin.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicAuthorizationInstruction {
    pub authorization_url: String,
    pub redirect_uri: String,
}

impl std::fmt::Debug for PublicAuthorizationInstruction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublicAuthorizationInstruction")
            .field("authorization_url", &"<redacted>")
            .field("redirect_uri", &"<redacted>")
            .finish()
    }
}

/// Opaque sender for the bounded native authorization-instruction queue.
#[derive(Clone)]
pub struct AuthorizationInstructionSender {
    sender: SyncSender<PublicAuthorizationInstruction>,
}

impl AuthorizationInstructionSender {
    pub(super) fn try_send(
        &self,
        instruction: PublicAuthorizationInstruction,
    ) -> Result<(), &'static str> {
        match self.sender.try_send(instruction) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err("ui_sink_full"),
            Err(TrySendError::Disconnected(_)) => Err("ui_sink_closed"),
        }
    }
}

/// Create a native queue with a fixed capacity of four instructions.
pub fn authorization_instruction_channel() -> (
    AuthorizationInstructionSender,
    Receiver<PublicAuthorizationInstruction>,
) {
    let (sender, receiver) = sync_channel(AUTHORIZATION_INSTRUCTION_QUEUE_CAPACITY);
    (AuthorizationInstructionSender { sender }, receiver)
}
