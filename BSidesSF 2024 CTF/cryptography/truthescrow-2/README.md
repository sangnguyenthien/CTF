
![image](https://github.com/sangnguyenthien/CTF/assets/89742084/2600f3dd-4fe7-433f-a478-ea3d82316a7d)


Like truthescrow-1, our task is calculate **d** from the leaked lower half bits of the private key **d** to create valid signature -> Read the truth from Citizen 1 (Nadia Heninger Hovav Shacham).


![image](https://github.com/sangnguyenthien/CTF/assets/89742084/2382e5e0-43ff-431a-bc1a-0dc359c2863d)

Maybe you will need this: https://eprint.iacr.org/2020/1506.pdf

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/732ccfa1-22e8-4316-a947-e3d3d43f3373)


Oh, i found something cool
Python implementations of cryptographic attacks and utilities.: https://github.com/jvdsn/crypto-attacks/tree/master

Here is what we need: https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/partial_key_exposure.py

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/5a3407d0-7d52-4eb9-b7b4-42b563e7c370)




![image](https://github.com/sangnguyenthien/CTF/assets/89742084/b2bf6fb6-ccb6-4040-92c6-5604877a9b5e)


Add the following code at the bottom of the partial_key_exposure.py file and run using ```sage -python attacks/rsa/partial_key_exposure.py```


```python
import logging

# Some logging so we can see what's happening.
logging.basicConfig(level=logging.DEBUG)

N = 0xb541c5e02f525039bda6599fc2d5f2d6adedb947f53a6609df0e5a35e30a6e9e6dddb9fd12a294ffa5ba58efd12a2b70146390a75c2c879662d24533170d3dbc1b26faab8344edf315c9c693aec6b903154e8762fc64b75399421150b0317964ba20d15384b6331639ed3e4bb0a5c26baef4a1d46a8db453bd55eaf029ccfc48e4285429a6298bbbbb3fff356af65decd23969ae32857617c3f4a6367e079830cd14202c80fe2f75b09442aa1012761c7c0b270b679006bb477ed8e721bc5a957f3e59d5511e09a234128312bfb3dd1d0741c72d3b019f592a799e6ec4c18bbb87f70eba9ec4c0f55558849aa90e16011ef86e71e65e9307cd19b617d17f52bf
e = 0x10001
partial_d = '????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????a4020e7c324236434a57148a68b5378a9eadff800fc81aa34bad43a1e414b8fb7408673ba448eea204f2328783d37a952b8dd7eb4d2bd71abd668276eb84ac2281d0c26f2c45fb580f4c7c6238effae75de9d9c2bc448eac8a908d6c4c55989d199cc997ed0690000eaa8f3843f34ca844dde0d82c4cb063b3eb52082e1fb7320d8fe151'

from shared.partial_integer import PartialInteger

partial_d = PartialInteger.from_hex_be(partial_d)

p,q,d=attack(N, e, partial_d)
assert p * q == N
print(f"Found {p = } and {q = } and {d = }")
```

GOT IT!

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/001c3ac5-2b5b-451d-9674-d69e30f8f006)


Just calculate signature for m = 66460002104482997899935341739632656173 (signature = m^d mod N)

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/6e2b2fa4-5879-4108-abd3-f8bab9718cfa)

Result:

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/d22c7ef8-a363-4d5e-8b2d-16f796484674)
