# Challenge: KCSBank
## Source: banking.zip
## Solution

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/0ed6d19d-2e29-49f8-b9f6-5e35e90acab5)

Demo qua 3 chức năng chính: reg, login và info

Hàm reg:

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/cf338d9c-35ca-4464-97b9-f337ba45a946)

Chúng ta có thể thấy rằng, lúc đầu fullname được lưu trên stack, sau đó nó dùng strdup() để nhân bản cái mảng này thành một mảng mới và lưu ở trên một vùng nhớ khác. Địa chỉ của mảng mới (lưu fullname) được trỏ bởi con trỏ qword_4070 (bss).


![image](https://github.com/sangnguyenthien/CTF/assets/89742084/9860ff00-bd55-4ac4-bca4-ab7bce100e2c)

----

Ở hàm info() có lỗi format string: printf(qword_4070)

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/e6b6b545-c7a8-4295-a553-859cec01f37a)


Vậy thì, lúc đăng ký chúng ta có thể đặt fullname thành "%p %21$p" hay đại khái thế, sau đó login và gọi info -> Leak dữ liệu trên thanh ghi và stack

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/0d13b304-0a2d-46e7-a1f0-58fe6e5307e8)


----
Mục tiêu của tôi là tận dụng lỗi format string để leak code base, leak địa chỉ libc và ghi đè địa chỉ trả về trong stack của main thành system("/bin/sh").
