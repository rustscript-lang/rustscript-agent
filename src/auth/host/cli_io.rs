//! Bounded native delivery of public device-login instructions.

use std::sync::{
    Arc,
    mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rustscript_vm::{CallOutcome, Value, Vm, VmResult};

use crate::auth::oauth::{OAuthCancel, OAuthClock, OAuthError, OAuthIoContext};
use crate::runtime::RunCancellation;

use super::{Bound, Owner, error, result};

const DEVICE_INSTRUCTION_QUEUE_CAPACITY: usize = 4;

/// Explicitly public device authorization instructions for a native UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicDeviceInstruction {
    pub verification_url: String,
    pub user_code: String,
    pub expires_in_seconds: u64,
}

/// Native implementations must honor the finite context during every blocking
/// step and acknowledge only after output completes. The host cannot preempt an
/// arbitrary synchronous sink that ignores this contract.
pub trait DeviceInstructionSink: Send + Sync {
    fn emit(
        &self,
        instruction: &PublicDeviceInstruction,
        context: &OAuthIoContext,
    ) -> Result<(), OAuthError>;
}

/// Opaque sender for one bounded device-instruction delivery path.
#[derive(Clone)]
pub struct DeviceInstructionSender {
    delivery: DeviceInstructionDelivery,
}

#[derive(Clone)]
enum DeviceInstructionDelivery {
    Queued(SyncSender<PublicDeviceInstruction>),
    Direct(Arc<dyn DeviceInstructionSink>),
}

impl DeviceInstructionSender {
    /// Create a direct sink whose return acknowledges completed native output.
    pub fn from_sink(sink: Arc<dyn DeviceInstructionSink>) -> Self {
        Self {
            delivery: DeviceInstructionDelivery::Direct(sink),
        }
    }
}

/// Create a native queue with a fixed capacity of four instructions.
pub fn device_instruction_channel() -> (DeviceInstructionSender, Receiver<PublicDeviceInstruction>)
{
    let (sender, receiver) = sync_channel(DEVICE_INSTRUCTION_QUEUE_CAPACITY);
    (
        DeviceInstructionSender {
            delivery: DeviceInstructionDelivery::Queued(sender),
        },
        receiver,
    )
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
        // `requested` is shared with the parent invocation; the child owns its own watcher.
        // The token can be cancelled independently of a typed run request.
        // OAuthIoContext checks the deadline separately.
        self.invocation.token().is_cancelled() || self.invocation.requested().is_some()
    }
}

struct OwnerOAuthCancel(Arc<Owner>);

impl OAuthCancel for OwnerOAuthCancel {
    fn is_cancelled(&self) -> bool {
        self.0.revoked.load(std::sync::atomic::Ordering::Acquire)
            || self.0.cancellation.token().is_cancelled()
            || self.0.cancellation.requested().is_some()
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

    match &sender.delivery {
        DeviceInstructionDelivery::Queued(sender) => match sender.try_send(instruction) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(error("ui_sink_full")),
            Err(TrySendError::Disconnected(_)) => return Err(error("ui_sink_closed")),
        },
        DeviceInstructionDelivery::Direct(sink) => {
            let context = OAuthIoContext::new(
                owner.deadline,
                Arc::new(SystemOAuthClock),
                Arc::new(OwnerOAuthCancel(Arc::clone(owner))),
            );
            owner.check()?;
            context.check().map_err(|_| error("policy_inactive"))?;
            let emitted = sink.emit(&instruction, &context);
            check_current_owner(vm, owner)?;
            owner.check()?;
            context.check().map_err(|_| error("policy_inactive"))?;
            if emitted.is_err() {
                return Err(error("ui_sink_closed"));
            }
        }
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

    if *expires_in_seconds <= 0
        || !crate::auth::device_output::valid_public_instruction(
            verification_url,
            user_code,
            *expires_in_seconds as u64,
        )
    {
        return Err(error("ui_instruction_invalid"));
    }

    Ok(PublicDeviceInstruction {
        verification_url: verification_url.to_string(),
        user_code: user_code.to_string(),
        expires_in_seconds: *expires_in_seconds as u64,
    })
}
