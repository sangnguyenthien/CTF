```python
from Crypto.Util.number import long_to_bytes
from pwn import *

after_swap = list("RMHSWIDUYOKNLJPBQFGZAVETXC")

middle = [0 for _ in range(26)]
v23 = [0 for _ in range(26)]
v23[0] = 0xA7
v23[1] = 0x86
v23[2] = 0x8E
v23[3] = 0x26
v23[4] = 0x92
v23[5] = 0x4C
v23[6] = 0x54
v23[7] = 0x6f
v23[8] = 0x1d
v23[9] = 0x96
v23[10] = 0xD4
v23[11] = 0x93
v23[12] = 0x8B
v23[13] = 0xA8
v23[14] = 0x28
v23[15] = 0xA9
v23[16] = 0x18
v23[17] = 0x9A
v23[18] = 0x6a
v23[19] = 0x5A
v23[20] = 0x3E
v23[21] = 0x9A
v23[22] = 0x27
v23[23] = 0x8B
v23[24] = 0xEE
v23[25] = 0x1C


alphabet = []

for i in range(26):
    alphabet.append(chr(0x41+i))

for i in range(26):
    index = alphabet.index(after_swap[i])
    middle[index] = v23[i]

print(middle)

plain = []
rand_val = [1804289383, 846930886, 1681692777, 1714636915, 1957747793, 424238335, 719885386, 1649760492, 596516649, 1189641421, 1025202362, 1350490027, 783368690, 1102520059, 2044897763, 1967513926, 1365180540, 1540383426, 304089172, 1303455736, 35005211, 521595368, 294702567, 1726956429, 336465782, 861021530]

for i in range(26):
    plain.append(middle[i] ^ rand_val[i] & 0xFF)
print(plain)

plain[25] = 0xa


win_payload = b""
for nu in plain:
    win_payload += long_to_bytes(nu)
print(win_payload)
write("win_payload", win_payload)
```
```python
from Crypto.Util.number import long_to_bytes
from pwn import *

after_swap = list("RMHSWIDUYOKNLJPBQFGZAVETXC")

middle = [0 for _ in range(26)]
v23 = [0 for _ in range(26)]
v23[0] = 0xA7
v23[1] = 0x86
v23[2] = 0x8E
v23[3] = 0x26
v23[4] = 0x92
v23[5] = 0x4C
v23[6] = 0x54
v23[7] = 0x6f
v23[8] = 0x1d
v23[9] = 0x96
v23[10] = 0xD4
v23[11] = 0x93
v23[12] = 0x8B
v23[13] = 0xA8
v23[14] = 0x28
v23[15] = 0xA9
v23[16] = 0x18
v23[17] = 0x9A
v23[18] = 0x6a
v23[19] = 0x5A
v23[20] = 0x3E
v23[21] = 0x9A
v23[22] = 0x27
v23[23] = 0x8B
v23[24] = 0xEE
v23[25] = 0x1C


alphabet = []

for i in range(26):
    alphabet.append(chr(0x41+i))

for i in range(26):
    index = alphabet.index(after_swap[i])
    middle[index] = v23[i]

print(middle)

plain = []
rand_val = [1804289383, 846930886, 1681692777, 1714636915, 1957747793, 424238335, 719885386, 1649760492, 596516649, 1189641421, 1025202362, 1350490027, 783368690, 1102520059, 2044897763, 1967513926, 1365180540, 1540383426, 304089172, 1303455736, 35005211, 521595368, 294702567, 1726956429, 336465782, 861021530]

for i in range(26):
    plain.append(middle[i] ^ rand_val[i] & 0xFF)
print(plain)

plain[25] = 0xa


win_payload = b""
for nu in plain:
    win_payload += long_to_bytes(nu)
print(win_payload)
write("win_payload", win_payload)

# b"You've been thunderstruck\n"
```


       
