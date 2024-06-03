```python
from ctypes import CDLL

libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')

seed = 0

libc.srand(0)

random_val = []
cipher = list("cioerosgaenessT   ns k urelh oLdTie heri nfdfR")



for i in range(46):
	random_val.append(libc.rand())

reverse_random = random_val[::-1]
for i in range(46):
	temp = cipher[i]
	cipher[i] = cipher[reverse_random[i]%46]
	cipher[reverse_random[i]%46] = temp
print("".join(cipher))
```
![image](https://github.com/sangnguyenthien/CTF/assets/89742084/a7feb2a1-2b0b-4cfa-96ca-08b67623c7bb)
