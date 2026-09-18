//! Agent-owned run cancellation vocabulary.
//!
//! Frozen core moved VM operation cancellation to [`OperationCancelReason`].
//! Agent run-level reasons keep the historical `CancellationReason` name as an
//! alias of that enum so request/deadline/resource-closed mapping stays 1:1.
//! The cloneable run flag is the vendored process-token type: it is not a VM
//! operation graph.

pub use crate::capabilities::vm_io::CancellationToken;
pub use rustscript_vm::operation::OperationCancelReason as CancellationReason;
