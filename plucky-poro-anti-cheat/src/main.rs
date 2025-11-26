use aya::maps::{HashMap, PerfEventArray};
use aya::programs::KProbe;
use aya::util::online_cpus;
use bytes::BytesMut;
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn, info};
use plucky_poro_anti_cheat_common::{
    SecurityEvent, EVENT_EXEC, EVENT_PTRACE, EVENT_VM_READ, EVENT_VM_WRITE,
};
use std::process::Command;
use tokio::signal;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the executable to protect
    #[arg(short, long)]
    executable: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    // Spawn the target process
    let mut child = Command::new(&args.executable)
        .spawn()
        .expect("Failed to spawn target process");
    let pid = child.id();
    info!("Spawned target process {} with PID: {}", args.executable, pid);

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/plucky-poro-anti-cheat"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // Populate PROTECTED_PIDS map
    {
        let mut protected_pids: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("PROTECTED_PIDS").unwrap())?;
        protected_pids.insert(pid, 1, 0)?;
        info!("Added PID {} to protected list", pid);
    }

    // Load and attach programs
    let program_ptrace: &mut KProbe = ebpf.program_mut("plucky_poro_ptrace").unwrap().try_into()?;
    program_ptrace.load()?;
    program_ptrace.attach("__x64_sys_ptrace", 0)?;

    let program_vm_readv: &mut KProbe = ebpf.program_mut("plucky_poro_vm_readv").unwrap().try_into()?;
    program_vm_readv.load()?;
    program_vm_readv.attach("__x64_sys_process_vm_readv", 0)?;

    let program_vm_writev: &mut KProbe = ebpf.program_mut("plucky_poro_vm_writev").unwrap().try_into()?;
    program_vm_writev.load()?;
    program_vm_writev.attach("__x64_sys_process_vm_writev", 0)?;

    let program_execve: &mut KProbe = ebpf.program_mut("plucky_poro_execve").unwrap().try_into()?;
    program_execve.load()?;
    program_execve.attach("__x64_sys_execve", 0)?;

    // Setup PerfEventArray for events
    // Use take_map to avoid borrowing ebpf
    let events_map = ebpf.take_map("EVENTS").unwrap();
    let mut events = PerfEventArray::try_from(events_map)?;

    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        let mut buf = events.open(cpu_id, None)?;
        let mut buf = tokio::io::unix::AsyncFd::new(buf)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let mut guard = buf.readable_mut().await.unwrap();
                let events = guard.get_inner_mut().read_events(&mut buffers).unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const SecurityEvent;
                    let event = unsafe { ptr.read_unaligned() };

                    let comm = std::str::from_utf8(&event.comm)
                        .unwrap_or("<unknown>")
                        .trim_end_matches('\0');

                    let event_type_str = match event.event_type {
                        EVENT_PTRACE => "PTRACE",
                        EVENT_VM_READ => "VM_READ",
                        EVENT_VM_WRITE => "VM_WRITE",
                        EVENT_EXEC => "EXEC",
                        _ => "UNKNOWN",
                    };

                    info!(
                        "SECURITY ALERT: Type={} PID={} Comm={}",
                        event_type_str, event.pid, comm
                    );
                }
                guard.clear_ready();
            }
        });
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    // Attempt to kill the child process on exit
    let _ = child.kill();

    Ok(())
}
