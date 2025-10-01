#!/usr/bin/env python3
"""
Простой инструмент: перечисляет процессы, командную строку, открытые файлы и сетевые сокеты.
"""
import psutil
import json
import sys

def dump_process(pid):
    try:
        p = psutil.Process(pid)
        info = {
            "pid": pid,
            "ppid": p.ppid(),
            "name": p.name(),
            "exe": p.exe(),
            "cmdline": p.cmdline(),
            "username": p.username(),
            "cwd": p.cwd(),
            "open_files": [f.path for f in p.open_files()],
            "connections": [
                {"fd": c.fd, "laddr": c.laddr._asdict() if c.laddr else None,
                 "raddr": c.raddr._asdict() if c.raddr else None,
                 "status": c.status}
                for c in p.connections()
            ],
        }
        return info
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return {"pid": pid, "error": str(e)}

def main():
    out = []
    for proc in psutil.process_iter(attrs=['pid']):
        pid = proc.info['pid']
        out.append(dump_process(pid))
    # pretty print JSON
    print(json.dumps(out, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
