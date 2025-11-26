import sys
import ctypes
import os
import errno

# Constants from sys/ptrace.h
PTRACE_ATTACH = 16

def attack_ptrace(pid):
    print(f"[*] Attempting PTRACE_ATTACH on PID {pid}...")
    
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    
    # long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
    libc.ptrace.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    libc.ptrace.restype = ctypes.c_long
    
    res = libc.ptrace(PTRACE_ATTACH, int(pid), None, None)
    
    if res == -1:
        err = ctypes.get_errno()
        print(f"[-] PTRACE_ATTACH failed with errno: {err} ({os.strerror(err)})")
        if err == errno.EPERM:
            print("[+] SUCCESS: Operation not permitted (Blocked by Anti-Cheat)")
            sys.exit(0)
        else:
            print("[-] FAILURE: Unexpected error code")
            sys.exit(1)
    else:
        print("[-] FAILURE: PTRACE_ATTACH succeeded (Anti-Cheat failed)")
        # Detach to be nice
        PTRACE_DETACH = 17
        libc.ptrace(PTRACE_DETACH, int(pid), None, None)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <PID>")
        sys.exit(1)
    
    attack_ptrace(sys.argv[1])