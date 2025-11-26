import sys
import ctypes
import os
import errno

def attack_vm_read(pid):
    print(f"[*] Attempting process_vm_readv on PID {pid}...")
    
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    
    class IOVEC(ctypes.Structure):
        _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]

    # Try to read from the ELF header location (0x400000)
    remote_addr = 0x400000 
    local_buf = ctypes.create_string_buffer(100)
    
    local_iov = IOVEC(ctypes.cast(local_buf, ctypes.c_void_p), 100)
    remote_iov = IOVEC(remote_addr, 100)
    
    libc.process_vm_readv.argtypes = [
        ctypes.c_int, 
        ctypes.POINTER(IOVEC), 
        ctypes.c_ulong, 
        ctypes.POINTER(IOVEC), 
        ctypes.c_ulong, 
        ctypes.c_ulong
    ]
    libc.process_vm_readv.restype = ctypes.c_ssize_t
    
    res = libc.process_vm_readv(
        int(pid), 
        ctypes.byref(local_iov), 
        1, 
        ctypes.byref(remote_iov), 
        1, 
        0
    )
    
    if res == -1:
        err = ctypes.get_errno()
        print(f"[-] process_vm_readv failed with errno: {err} ({os.strerror(err)})")
        if err == errno.EPERM:
            print("[+] SUCCESS: Operation not permitted (Blocked by Anti-Cheat)")
            sys.exit(0)
        else:
            print(f"[-] FAILURE: Unexpected error code (Expected EPERM)")
            sys.exit(1)
    else:
        print("[-] FAILURE: process_vm_readv succeeded (Anti-Cheat failed)")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <PID>")
        sys.exit(1)
    
    attack_vm_read(sys.argv[1])