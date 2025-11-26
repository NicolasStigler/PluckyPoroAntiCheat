#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_override_return, bpf_probe_read_kernel,
        bpf_probe_read_user, bpf_probe_read_user_buf,
    },
    macros::{kprobe, map},
    maps::{HashMap, PerfEventArray},
    programs::ProbeContext,
};
use aya_log_ebpf::info;
use plucky_poro_anti_cheat_common::{
    SecurityEvent, EVENT_EXEC, EVENT_PTRACE, EVENT_VM_READ, EVENT_VM_WRITE,
};

#[map]
static PROTECTED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static EVENTS: PerfEventArray<SecurityEvent> = PerfEventArray::new(0);

const PTRACE_TRACEME: u64 = 0;
const EPERM: i64 = -1;
const MAX_ENV_VARS: u32 = 64;
const LD_PRELOAD_LEN: usize = 11;
const LD_PRELOAD_PREFIX: [u8; 11] = *b"LD_PRELOAD=";

#[kprobe]
pub fn plucky_poro_ptrace(ctx: ProbeContext) -> u32 {
    match try_plucky_poro_ptrace(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_plucky_poro_ptrace(ctx: ProbeContext) -> Result<u32, u32> {
    // We assume we are attached to __x64_sys_ptrace
    // Arg0 is *mut pt_regs
    let regs_ptr: *const u8 = ctx.arg(0).ok_or(0u32)?;

    // x86_64 pt_regs offsets
    // rdi (arg1: request) is at offset 112
    // rsi (arg2: pid) is at offset 104
    let request: u64 =
        unsafe { bpf_probe_read_kernel(regs_ptr.add(112) as *const u64).map_err(|_| 0u32)? };
    let pid: u32 =
        unsafe { bpf_probe_read_kernel(regs_ptr.add(104) as *const u64).map_err(|_| 0u32)? } as u32;

    // Check PTRACE_TRACEME (target is self)
    if request == PTRACE_TRACEME {
        let current_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        if unsafe { PROTECTED_PIDS.get(&current_pid) }.is_some() {
            info!(
                &ctx,
                "Blocked PTRACE_TRACEME on protected PID {}", current_pid
            );
            let comm = bpf_get_current_comm().unwrap_or([0; 16]);
            let event = SecurityEvent {
                pid: current_pid,
                event_type: EVENT_PTRACE,
                comm,
            };
            EVENTS.output(&ctx, &event, 0);
            unsafe { bpf_override_return(ctx.regs, EPERM as u64) };
            return Ok(0);
        }
    } else {
        // Check PTRACE_ATTACH and others (target is pid arg)
        if unsafe { PROTECTED_PIDS.get(&pid) }.is_some() {
            info!(
                &ctx,
                "Blocked PTRACE request {} on protected PID {}", request, pid
            );
            let current_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            let comm = bpf_get_current_comm().unwrap_or([0; 16]);
            let event = SecurityEvent {
                pid: current_pid,
                event_type: EVENT_PTRACE,
                comm,
            };
            EVENTS.output(&ctx, &event, 0);
            unsafe { bpf_override_return(ctx.regs, EPERM as u64) };
            return Ok(0);
        }
    }

    Ok(0)
}

#[kprobe]
pub fn plucky_poro_vm_readv(ctx: ProbeContext) -> u32 {
    match try_plucky_poro_vm_rw(ctx, "readv") {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[kprobe]
pub fn plucky_poro_vm_writev(ctx: ProbeContext) -> u32 {
    match try_plucky_poro_vm_rw(ctx, "writev") {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[kprobe]
pub fn plucky_poro_execve(ctx: ProbeContext) -> u32 {
    match try_plucky_poro_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_plucky_poro_vm_rw(ctx: ProbeContext, op: &str) -> Result<u32, u32> {
    // Arg0 is *mut pt_regs
    let regs_ptr: *const u8 = ctx.arg(0).ok_or(0u32)?;

    // x86_64 pt_regs offsets
    // rdi (arg1: pid) is at offset 112
    let target_pid: u32 =
        unsafe { bpf_probe_read_kernel(regs_ptr.add(112) as *const u64).map_err(|_| 0u32)? } as u32;

    if unsafe { PROTECTED_PIDS.get(&target_pid) }.is_some() {
        let current_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        // Allow self-access (though process_vm_readv is usually for cross-process)
        if current_pid != target_pid {
            info!(
                &ctx,
                "Blocked process_vm_{} on protected PID {} from PID {}",
                op,
                target_pid,
                current_pid
            );
            let comm = bpf_get_current_comm().unwrap_or([0; 16]);
            let event_type = if op == "readv" {
                EVENT_VM_READ
            } else {
                EVENT_VM_WRITE
            };
            let event = SecurityEvent {
                pid: current_pid,
                event_type,
                comm,
            };
            EVENTS.output(&ctx, &event, 0);
            unsafe { bpf_override_return(ctx.regs, EPERM as u64) };
            return Ok(0);
        }
    }

    Ok(0)
}

fn try_plucky_poro_execve(ctx: ProbeContext) -> Result<u32, u32> {
    let current_pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Only check protected processes
    if unsafe { PROTECTED_PIDS.get(&current_pid) }.is_none() {
        return Ok(0);
    }

    // Arg0 is *mut pt_regs
    let regs_ptr: *const u8 = ctx.arg(0).ok_or(0u32)?;

    // RDX is 3rd arg (envp) -> offset 96
    let envp_ptr_ptr: *const *const u8 = unsafe {
        let val: u64 = bpf_probe_read_kernel(regs_ptr.add(96) as *const u64).map_err(|_| 0u32)?;
        val as *const *const u8
    };

    if envp_ptr_ptr.is_null() {
        return Ok(0);
    }

    for i in 0..MAX_ENV_VARS {
        // Read envp[i]
        // We use bpf_probe_read_user because envp array is in user space
        let env_var_ptr: *const u8 = unsafe {
            bpf_probe_read_user(envp_ptr_ptr.add(i as usize)).map_err(|_| 0u32)?
        };

        if env_var_ptr.is_null() {
            break;
        }

        // Read start of string
        let mut buf = [0u8; LD_PRELOAD_LEN];
        unsafe {
            // Read string from user space
            if bpf_probe_read_user_buf(env_var_ptr, &mut buf).is_err() {
                continue;
            }
        }

        // Compare
        let mut match_found = true;
        for j in 0..LD_PRELOAD_LEN {
            if buf[j] != LD_PRELOAD_PREFIX[j] {
                match_found = false;
                break;
            }
        }

        if match_found {
            info!(
                &ctx,
                "Blocked LD_PRELOAD execve on protected PID {}", current_pid
            );
            let comm = bpf_get_current_comm().unwrap_or([0; 16]);
            let event = SecurityEvent {
                pid: current_pid,
                event_type: EVENT_EXEC,
                comm,
            };
            EVENTS.output(&ctx, &event, 0);
            unsafe { bpf_override_return(ctx.regs, EPERM as u64) };
            return Ok(0);
        }
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
