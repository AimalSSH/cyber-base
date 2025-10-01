#!/usr/bin/env python3
"""
Создаёт большой буфер в памяти, записывает в него маркерную строку и ждёт.
Используется для PoC чтения памяти другим процессом.
"""
import time
import mmap
import ctypes
import os

MARKER = b"SECRET_MARKER_AYMAL_1234567890"  # видимый маркер
BUF_SIZE = 1024 * 1024  # 1 MB

def allocate_buffer():
    # Создадим анонимный mmap (rw)
    mm = mmap.mmap(-1, BUF_SIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE)
    # Запишем маркер в начало
    mm.seek(0)
    mm.write(MARKER)
    # Поддержим buffer в памяти: вернём mm объект и адрес через ctypes
    address = ctypes.addressof(ctypes.c_char.from_buffer(mm))
    return mm, address

def main():
    mm, addr = allocate_buffer()
    pid = os.getpid()
    print(f"victim: pid={pid} marker={MARKER.decode()} addr={hex(addr)} size={BUF_SIZE}")
    print("victim: sleeping. Run attacker on this pid.")
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("victim: exiting")

if __name__ == "__main__":
    main()
