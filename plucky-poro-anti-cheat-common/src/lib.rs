#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct SecurityEvent {
    pub pid: u32,
    pub event_type: u32, // 1: Ptrace, 2: Memory, 3: Exec
    pub comm: [u8; 16],
}

// Event Types
pub const EVENT_PTRACE: u32 = 1;
pub const EVENT_VM_READ: u32 = 2;
pub const EVENT_VM_WRITE: u32 = 3;
pub const EVENT_EXEC: u32 = 4;
