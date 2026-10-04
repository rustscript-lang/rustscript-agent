//! Bounded native delivery of public device-login instructions.

use std::sync::{
    Arc,
    mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rustscript_vm::{CallOutcome, Value, Vm, VmResult};
use url::Url;

use crate::auth::oauth::{OAuthCancel, OAuthClock};
use crate::runtime::RunCancellation;

use super::{Bound, Owner, error, result};

const DEVICE_INSTRUCTION_QUEUE_CAPACITY: usize = 4;
const MAX_VERIFICATION_URL_BYTES: usize = 2048;
const MAX_USER_CODE_BYTES: usize = 128;
const SECRET_QUERY_KEYS: &[&str] = &[
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "device_code",
    "device_id",
    "device_auth_id",
    "authorization_code",
    "code_verifier",
    "code",
    "state",
];

/// Explicitly public device authorization instructions for a native UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicDeviceInstruction {
    pub verification_url: String,
    pub user_code: String,
    pub expires_in_seconds: u64,
}

/// Opaque sender for one bounded device-instruction queue.
#[derive(Clone)]
pub struct DeviceInstructionSender {
    sender: SyncSender<PublicDeviceInstruction>,
}

/// Create a native queue with a fixed capacity of four instructions.
pub fn device_instruction_channel() -> (DeviceInstructionSender, Receiver<PublicDeviceInstruction>)
{
    let (sender, receiver) = sync_channel(DEVICE_INSTRUCTION_QUEUE_CAPACITY);
    (DeviceInstructionSender { sender }, receiver)
}

/// Production wall clock for generic OAuth primitives.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemOAuthClock;

impl OAuthClock for SystemOAuthClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis().min(i64::MAX as u128) as u64)
            .unwrap_or(0)
    }
}

/// OAuth cancellation view scoped to one invocation child.
pub struct RunOAuthCancel {
    invocation: RunCancellation,
}

impl RunOAuthCancel {
    pub fn new(cancellation: RunCancellation) -> Self {
        Self {
            invocation: cancellation.child(),
        }
    }
}

impl OAuthCancel for RunOAuthCancel {
    fn is_cancelled(&self) -> bool {
        // A deadline is checked separately by OAuthIoContext. `requested` is
        // shared with the parent invocation; the child owns its own watcher.
        self.invocation.requested().is_some()
    }
}

pub(super) fn emit_device_instruction_call(
    vm: &mut Vm,
    args: &[Value],
    owner: &Arc<Owner>,
) -> VmResult<CallOutcome> {
    check_current_owner(vm, owner)?;
    owner.check()?;

    let Some(sender) = owner.device_instruction_sender.as_ref() else {
        return Err(error("ui_unavailable"));
    };
    let instruction = parse_instruction(args)?;
    check_current_owner(vm, owner)?;
    owner.check()?;
    match sender.sender.try_send(instruction) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => return Err(error("ui_sink_full")),
        Err(TrySendError::Disconnected(_)) => return Err(error("ui_sink_closed")),
    }

    check_current_owner(vm, owner)?;
    owner.check()?;
    result(Value::Bool(true))
}

fn check_current_owner(vm: &mut Vm, owner: &Arc<Owner>) -> VmResult<()> {
    let current = vm
        .host_context()
        .scope_state::<Bound>()
        .map(|bound| Arc::clone(&bound.0))
        .ok_or_else(|| error("host_unbound"))?;
    if !Arc::ptr_eq(&current, owner) {
        return Err(error("owner_mismatch"));
    }
    Ok(())
}

fn parse_instruction(args: &[Value]) -> VmResult<PublicDeviceInstruction> {
    let Some(Value::String(verification_url)) = args.first() else {
        return Err(error("ui_instruction_invalid"));
    };
    let Some(Value::String(user_code)) = args.get(1) else {
        return Err(error("ui_instruction_invalid"));
    };
    let Some(Value::Int(expires_in_seconds)) = args.get(2) else {
        return Err(error("ui_instruction_invalid"));
    };

    if verification_url.is_empty()
        || verification_url.len() > MAX_VERIFICATION_URL_BYTES
        || verification_url.chars().any(char::is_control)
        || user_code.is_empty()
        || user_code.len() > MAX_USER_CODE_BYTES
        || user_code.chars().any(char::is_control)
        || *expires_in_seconds <= 0
    {
        return Err(error("ui_instruction_invalid"));
    }

    let parsed = Url::parse(verification_url).map_err(|_| error("ui_instruction_invalid"))?;
    if parsed.scheme() != "https"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || parsed.query_pairs().any(|(name, _)| {
            SECRET_QUERY_KEYS
                .iter()
                .any(|secret| name.eq_ignore_ascii_case(secret))
        })
    {
        return Err(error("ui_instruction_invalid"));
    }

    Ok(PublicDeviceInstruction {
        verification_url: verification_url.to_string(),
        user_code: user_code.to_string(),
        expires_in_seconds: *expires_in_seconds as u64,
    })
}
