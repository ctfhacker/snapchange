//! Implements `VirtualSnapshot` to save/restore a state in the middle of an execution

use kvm_bindings::{kvm_fpu, kvm_regs, kvm_sregs};

use crate::FxIndexMap;
use crate::PhysAddr;

/// A virtual snapshot taken in the middle of an execution. Ability to save/store
/// a state after the original snapshot was taken.
#[derive(Debug)]
pub struct VirtualSnapshot {
    /// The memory diff after the clean snapshot to restore to this snapshot
    pub memory: FxIndexMap<PhysAddr, Vec<u8>>,

    /// Register state
    pub regs: kvm_regs,

    /// Register state
    pub sregs: kvm_sregs,

    /// FPU regs
    pub fpu: kvm_fpu,
}
