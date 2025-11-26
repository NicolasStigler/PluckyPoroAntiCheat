# PluckyPoroAntiCheat

Plucky Poro Anti-Cheat is specifically designed for Linux and aims to address game devs concerns about cheating by utilizing eBPF for efficient monitoring without requiring intrusive kernel drivers (like Windows ACs) or kernel modules. Its goal is to achieve feature parity with systems like Vanguard and EAC.

## Name Inspiration

Plucky Poro
> "New recruit has the kind of endurance and courage shown by our finest soldiers. Will he make it to the **Vanguard** someday? He's... smaller than the rest, but we'll see." — Vanguard Sergeant

## Architecture

The system employs a hybrid **Event-Driven Observability** model, leveraging eBPF for safe, high-performance kernel instrumentation and Rust for a robust user-space control plane.

*   **Kernel-Space Probe (eBPF/Rust):**
    *   Utilizes `kprobe` programs injected into the kernel.
    *   Intercepts critical syscalls (`ptrace`, `process_vm_readv`, `execve`).
    *   Performs in-kernel filtering to minimize context-switch overhead.
    *   Enforces security policies directly in the kernel (returning `-EPERM` on violations).

*   **User-Space Control Plane (Rust/Tokio):**
    *   Daemon service responsible for loading eBPF bytecode.
    *   Manages the lifecycle of the protected process.
    *   Consumes security events from a shared `PerfEventArray` ring buffer.
    *   Handles policy management and logging.

## Implemented Modules

### 1. Anti-Debugging Module
*   **Threat:** Dynamic analysis and code injection via debuggers (GDB, Cheat Engine).
*   **Implementation:** Hooks `sys_ptrace`.
*   **Logic:** Intercepts `PTRACE_ATTACH` and `PTRACE_TRACEME` targeting the protected PID. Immediately blocks the attempt.

### 2. Memory Isolation Module
*   **Threat:** External memory manipulation (RPM/WPM) via `process_vm_readv` / `process_vm_writev`.
*   **Implementation:** Hooks `sys_process_vm_readv` and `sys_process_vm_writev`.
*   **Logic:** Validates source PID against authorized hierarchy. Blocks unauthorized access to the protected process's virtual memory.

### 3. Execution Integrity Module
*   **Threat:** Runtime library injection via `LD_PRELOAD`.
*   **Implementation:** Hooks `sys_execve`.
*   **Logic:** Inspects `envp` pointers during process spawn. Flags and terminates execution if suspicious `LD_PRELOAD` patterns are detected.

## Project Structure

*   `plucky-poro-anti-cheat`: User-space agent (Control Plane).
*   `plucky-poro-anti-cheat-ebpf`: Kernel-space eBPF probes.
*   `plucky-poro-anti-cheat-common`: Shared types and constants.
*   `xtask`: Build automation tool.
*   `tests/`: Integration tests and verification scripts.

## Building and Running

### Prerequisites
*   Rust Nightly Toolchain
*   `bpf-linker`
*   `cargo-generate`

### Build
```bash
cargo build --release
```

### Run
```bash
sudo ./target/release/plucky-poro-anti-cheat --executable <path_to_game_binary>
```

## Testing & Verification

A comprehensive verification suite is included to ensure all modules are functioning correctly.

### Test Suite (`tests/`)
*   **Victim Application:** A dummy C program (`victim.c`) that simulates a game process.
*   **Attacker Scripts:**
    *   `attacker_ptrace.py`: Attempts to attach GDB-like tracers.
    *   `attacker_vm_read.py`: Attempts to read memory from the victim.
    *   `run_verification.sh`: Automates the entire test flow.

### Running Tests
```bash
chmod +x tests/run_verification.sh
./tests/run_verification.sh
```

**Expected Output:**
The script will compile the victim, run the agent, and execute attacks. Success is indicated by `[PASS]` for blocking PTRACE, VM_READ, and LD_PRELOAD attempts, and confirming logs are generated.

## Roadmap

To bridge the gap between this implementation and enterprise-grade solutions (Vanguard/EAC), the following architectural enhancements are planned. These features focus on **Zero Trust** principles, **Hardware Attestation**, and **Behavioral Heuristics**.

### Phase 1: Platform Integrity & Attestation
* **TPM 2.0 / Secure Boot Validation:** Implement a module to verify the boot chain and TPM PCR registers, ensuring the kernel hasn't been tampered with before the agent loaded (similar to Vanguard's Trusted Boot requirement, which I can't test right now because my Arch system doesn't have Secure Boot implemented).
* **Hardware Fingerprinting (HWID):** Generate unique device identifiers based on SMBIOS, GPU UUIDs, and Disk Serials to enable persistent hardware bans, preventing banned users from simply creating new accounts.
* **IOMMU Group Enforcement:** Mitigate **DMA (Direct Memory Access)** attacks—where hardware cheats read memory physically—by enforcing strict IOMMU groupings and alerting on unauthorized PCIe device enumeration (Need to read more theory about this stuff).

### Phase 2: Behavioral Heuristics & Telemetry
* **HID Entropy Analysis:** Instead of just checking memory, analyze mouse/keyboard input streams via eBPF.
    * *Goal:* Detect synthetic inputs (Aimbots/Triggerbots) by calculating the entropy of movement vectors. Machines are "too perfect", while humans are noisy (Need to carefully check this because I remember MC cheat clients had "legit" modules that tried to mimic that noise).
* **Stack Walking & Return Address Checks:** Periodically pause threads and inspect the call stack.
    * *Goal:* Detect "ROP Chains" or calls originating from non-executable memory regions (typical of manual mapping injections).

### Phase 3: Agent Self-Protection
* **Heartbeat & Watchdog:** Implement a cryptographic heartbeat between the Kernel Probe and User-Space Agent. If the User-Space agent is killed or paused (via `SIGSTOP`), the eBPF probe triggers a system panic or terminates the game session immediately.
* **Obfuscation & Anti-Tamper:** Implement virtualization checks (Red Pill/Check's like [VMAware](https://github.com/kernelwernel/VMAware)) to detect if the game is running inside a VM or Hypervisor used for introspection.

## License

With the exception of eBPF code, PluckyPoroAntiCheat is distributed under the terms of the MIT license or the Apache License (version 2.0), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the GNU General Public License, Version 2 or the MIT license, at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the GPL-2 license, shall be dual licensed as above, without any additional terms or conditions.

---
*Disclaimer: This project is for educational and research purposes. It demonstrates how modern eBPF technology can create performant security observability in Linux environments.*