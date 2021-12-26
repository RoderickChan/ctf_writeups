from pwn import *

sh = ssh(user='ctf', host='node3.buuoj.cn', port=25102, password='guest', level='debug')

sh.interactive()