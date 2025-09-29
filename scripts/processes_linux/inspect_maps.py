#!/usr/bin/env python3
"""
Читает /proc/<pid>/maps и выводит сегменты с правами чтения-записи (rw).
Используется для понимания, где в памяти можно искать данные.
"""
import sys
import re

def parse_maps(pid):
    path = f"/proc/{pid}/maps"
    regions = []
    with open(path, 'r') as f:
        for line in f:
            # example line:
            # 00400000-0040b000 r--p 00000000 08:02 131073 /usr/bin/cat
            m = re.match(r'([0-9a-fA-F]+)-([0-9a-fA-F]+) (\S{4}) (\S+) (\S+):(\S+) (\d+)\s*(.*)', line)
            if not m:
                continue
            start = int(m.group(1), 16)
            end = int(m.group(2), 16)
            perms = m.group(3)
            offset = m.group(4)
            dev = m.group(5) + ':' + m.group(6)
            inode = m.group(7)
            pathname = m.group(8).strip()
            regions.append({
                "start": start,
                "end": end,
                "perms": perms,
                "size": end - start,
                "pathname": pathname
            })
    return regions

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 inspect_maps.py <pid>")
        return
    pid = sys.argv[1]
    regs = parse_maps(pid)
    rw = [r for r in regs if 'r' in r['perms'] and 'w' in r['perms']]
    for r in rw:
        print(f"{hex(r['start'])}-{hex(r['end'])} ({r['size']} bytes) perms={r['perms']} path='{r['pathname']}'")

if __name__ == "__main__":
    main()
