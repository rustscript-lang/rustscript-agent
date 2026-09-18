//! Blocking host-op wait with an embedder cancel callback.
//!
//! Frozen core dropped `Vm::wait_for_host_op_blocking_with_cancel`. The runner
//! still needs to abort a pending host op when a run deadline or request fires,
//! so this helper polls the public `poll_waiting_host_op` surface.

use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use rustscript_vm::{Vm, VmError, VmResult};

fn noop_raw_waker() -> RawWaker {
    fn clone(_: *const ()) -> RawWaker {
        noop_raw_waker()
    }
    fn wake(_: *const ()) {}
    fn wake_by_ref(_: *const ()) {}
    fn drop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
    RawWaker::new(std::ptr::null(), &VTABLE)
}

/// Waits for the current host op, aborting when `cancelled` becomes true.
pub fn wait_for_host_op_blocking_with_cancel(
    vm: &mut Vm,
    mut cancelled: impl FnMut() -> bool,
) -> VmResult<()> {
    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    loop {
        if cancelled() {
            return Err(VmError::HostError(
                "host operation wait was cancelled".to_string(),
            ));
        }
        match vm.poll_waiting_host_op(&mut cx) {
            Poll::Ready(result) => return result,
            Poll::Pending => std::thread::sleep(std::time::Duration::from_millis(1)),
        }
    }
}
