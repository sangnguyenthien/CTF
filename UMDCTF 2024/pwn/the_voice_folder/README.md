# Challenge: the_voice
## Description
![image](https://github.com/sangnguyenthien/CTF/assets/89742084/dc760017-74d6-4bc8-aedb-587cb47953b9)
## Source
> the_voice

> the_voice.c

> Dockerfile

## Solution
Đầu tiên, tôi sẽ thử kiểm tra file thực thi bằng checksec
![image](https://github.com/sangnguyenthien/CTF/assets/89742084/69c6389e-ee54-436a-b807-a49b80e8767a)
Ok, với "No PIE" (Position Independent Executable) có nghĩa là mỗi khi bạn chạy file thì nó sẽ được tải vào địa chỉ cố định trong bộ nhớ.

C code:

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/89f3b087-47e8-40da-9680-016cecd43387)

Pseudocode sinh từ IDA Pro:

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/27a04fc3-60e5-49bc-8bf9-995d593e8703)
![image](https://github.com/sangnguyenthien/CTF/assets/89742084/d1358de2-c2c8-4342-8d32-e01a425b34be)

Chúng ta có thể thấy rằng có lỗi buffer overflow ở gets(nptr) (IDA main+11) cho phép chúng ta nhập input với độ dài tùy ý.

Nhưng vì chương trình được bảo vệ bởi Stack canary

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/82324c16-0410-4454-8206-caab24e5bc44)

Nên nếu mục đích của chúng ta là ghi đè bằng để sửa saved RIP (return address) thành địa chỉ của hàm give_flag() thì sẽ không được vì khi canary bị thay đổi dù chỉ 1 byte thì chương trình cũng sẽ toang và không thực hiện hàm give_flag() cho chúng ta.

Vậy làm thế nào?.
Chúng ta để ý ở IDA main+11 và main+12
```
  gets(nptr);
  __writefsqword(8 * atoi(nptr) - 80, 0x27CFuLL);
```
Dưới đây là assembly code của 2 câu lệnh này:
![image](https://github.com/sangnguyenthien/CTF/assets/89742084/62a63b7a-e632-4ee1-ac59-ae7451d754fd)
Đại khái là nó sẽ cho user input, xong nó sử dụng atoi() để chuyển cái string đấy thành số nguyên (số nguyên trả về được lưu trong thanh ghi eax). Ví dụ "11" -> 11.

Tiếp theo, câu lệnh ở địa chỉ 0x4012EB sẽ thực hiện ghi quadword 0x27CF vào địa chỉ: fsbase+0x0FFFFFFFFFFFFFFB0+rax*8
Chúng ta có thể điều chỉnh rax để ghi vào 1 chỗ nào đấy trên FS Segment... Canary được lưu ở...
![image](https://github.com/sangnguyenthien/CTF/assets/89742084/d61d032c-bedb-4746-abff-2dbafcaf0354)

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/ce2de1c0-5239-478b-8432-74b996a43bf0)

BINGO, canary của chúng ta được lưu ở fsbase+0x28. Thì nếu như chúng ta điều chỉnh input (nôm na là rax) để ghi được quadword 0x27CF vào địa chỉ fsbase+0x28, sau đó chúng ta lợi dụng buffer overflow để ghi đè canary trong stack của hàm main thành quadword 0x27CF. Trước khi trả về (return) thì nó sẽ kiểm tra xem 2 giá trị trên fsbase+0x28 và canary trên stack của main có giống nhau không (giống nhau và bằng 0x27CF) -> Chúng ta đã bypass được canary.
Phương trình cần giải của chúng ta:
> fsbase+0x28 = fsbase+0x0FFFFFFFFFFFFFFB0+rax*8

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/1f205eb2-5179-41ea-99e7-94ee0f35408a)

Suy ra, rax sẽ là 15. Việc còn lại là viết payload để ret2win ^^


Giá trị canary (fs:0x28) trước khi bị ghi đè: 0xdcf73fe8cdce6500
![image](https://github.com/sangnguyenthien/CTF/assets/89742084/4518911d-5278-431e-92a6-0624efc22a18)


Sau khi bị ghi đè: 0x00..27cf

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/fb2afec6-fe12-46a7-948b-f35ae2fe0f2e)


Tất nhiên là phải thay đổi canary trên stack (ở vị trí rbp-0x8) và return address thành địa chỉ của give_flag()

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/20c13bfe-6e69-4465-8562-26157afed777)


Code giải:
```python
from pwn import *

#pwn/the_voice

#fsbase + x*8-0x50 = fsbase + 0x28

#p = remote("challs.umdctf.io", 31192)
p = process("./the_voice")
input()
payload = b"15 "
payload += b"A"*21
payload += p64(0x27CF)
payload += p64(0)
payload += p64(0x4011F6)
write("payload", payload)

p.sendlineafter(b"command me to give it to you.", payload)
p.interactive()
```
