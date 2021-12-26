#! /usr/bin/python3
from pwncli import *

cli_script()

def allocate(p:tube, size):
    p.sendlineafter("Command: ", "1")
    p.sendlineafter("Size: ", str(size))
    p.recvline()


def update(p:tube, idx, size, content):
    p.sendlineafter("Command: ", "2")
    p.sendlineafter("Index: ", str(idx))
    p.sendlineafter("Size: ", str(size))
    p.sendafter("Content: ", content)
    p.recvline()

def delete(p:tube, idx):
    p.sendlineafter("Command: ", "3")
    p.sendlineafter("Index: ", str(idx))
    p.recvline()


def view(p:tube, idx):
    p.sendlineafter("Command: ", "4")
    p.sendlineafter("Index: ", str(idx))
    msg = p.recvuntil("1. Allocate\n")
    info("msg recv: {}".format(msg))
    return msg

def attack(p:tube):
    pass

attack(gift['io'])

