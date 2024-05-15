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
Kiểm tra protection: vậy là không thể ghi đè GOT
![image](https://github.com/sangnguyenthien/CTF/assets/89742084/4ce4bb51-c326-475f-8878-8550949d73be)


----
Mục tiêu của tôi là tận dụng lỗi format string để leak code base, leak địa chỉ libc và ghi đè địa chỉ trả về trong stack của main thành system("/bin/sh") (Leak thêm địa chỉ stack).

----
Chúng ta được cho Dockerfile để build. Vậy thì hãy lấy libc từ container

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/87040450-2ce7-4fad-92db-14937ed996a6)

Oke sau đó dùng pwninit để patch, và chúng ta có file banking_patched.

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/6ac49bf6-e3e7-4376-a23d-3c8d2dcb23f2)

----
Tiếp theo, đặt breakpoint ở câu lệnh printf có lỗi format string để xem stack địa chỉ gì hữu ích

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/d596fb25-0c49-46ef-b17c-61531db73519)

Sử dụng GDB

![leak base and libc](https://github.com/sangnguyenthien/CTF/assets/89742084/6c583146-130a-405e-ada8-09e14f38d0c7)

Như hình ta có thể thấy: sử dụng **%7$p** (địa chỉ **+0x0008**) để leak code base, sử dụng **%11$p** (địa chỉ **+0x0028**) để leak địa chỉ của libc và sử dụng **%6$p** (địa chỉ **+0x0000**) để leak địa chỉ stack (ở trên hình là **0x00007fffffffd9f0** sau này dùng tôi sẽ nói kỹ hơn).

Viết script và chạy thử:

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/0ba9080c-fcaa-4ada-96d9-09d6878669b7)

Oke ngon rồi

----

Bước tiếp theo, chúng ta sẽ chuẩn bị một số thứ cho việc ghi đè return address (saved RIP).
Đâu sẽ là return address (Saved RIP) của main?

![calculate_address_to_overwrite](https://github.com/sangnguyenthien/CTF/assets/89742084/578cb750-dcfa-4942-98d7-47dc7a2ba695)

Hãy sử dụng GDB, đặt breakpoint ngay trước khi main **ret**

![calculate_address_to_overwrite1](https://github.com/sangnguyenthien/CTF/assets/89742084/e8f60e78-36ee-4614-ad12-9ceae44b10ce)

Bingo: return address đang được lưu tại địa chỉ **0x00007fffffffda18**, địa chỉ leak được của stack là **0x00007fffffffd9f0** --> Khi viết script thì tính offset là được (**target address** (địa chỉ chúng ta cần ghi dữ liệu vào) = leak stack + 0x28).

![calculate_offset_overwrite_main](https://github.com/sangnguyenthien/CTF/assets/89742084/3e27b134-764b-45e5-996f-d75c704ab2c1)

----

Oke, đây là bước cuối cùng, để có thể ghi dữ liệu vào một địa chỉ thì chúng ta cần địa chỉ đó ở trên stack và dùng %n để ghi.

Hãy dùng GDB để xem thử, vẫn để breakpoint là ở câu lệnh có lỗi format string

![password](https://github.com/sangnguyenthien/CTF/assets/89742084/adbb0bef-941d-466a-afcd-6d3de0759116)

Hmm, có vẻ password vẫn còn ở trên stack lúc chúng ta login xong. Hãy kiểm tra lại để chắc chắn.
Register 1 tài khoản với mật khẩu "12345678" xem sao.

![password1](https://github.com/sangnguyenthien/CTF/assets/89742084/e30bb785-4f1f-4fc7-98a6-8162c3142446)

![password2](https://github.com/sangnguyenthien/CTF/assets/89742084/83b060cc-42be-4ffa-bb3d-056662cc9d00)

Oke rồi, vậy ý tưởng của tôi sẽ là register 1 tài khoản mới với password là địa chỉ mục tiêu (**target address**, cụ thể là địa chỉ đang lưu địa chỉ trả về của **main**) và fullname là payload của chúng ta: sử dụng **%20$hn** để ghi 2 bytes 1 lần, chứ ghi 4 bytes thì có thể lỗi hoặc hơi lâu... (**20 = (0x70-0x00)/8 + 6**). Sau đó login -> info

Những thứ chúng ta cần ghi đè là: pop rdi; ret; + địa chỉ của "/bin/sh" + địa chỉ của system. 

![address_of_pop_rdi](https://github.com/sangnguyenthien/CTF/assets/89742084/1ba55172-afcf-41d9-aa12-79c592aea61d)
![address_of_ret](https://github.com/sangnguyenthien/CTF/assets/89742084/d069cc94-075b-487f-bbc5-442247dbfa73)
![address_of_binsh](https://github.com/sangnguyenthien/CTF/assets/89742084/1c7cce26-facc-4e8f-9d8c-4aa278eb0035)

Test: 
![stackalignment](https://github.com/sangnguyenthien/CTF/assets/89742084/1eccb86d-0e91-4f34-b2d9-49604f43f7b3)


Bạn có thể bị lỗi như hình dưới, nếu bị lỗi hãy thêm "ret;" gadget vào payload ngay trước khi gọi system để căn chỉnh stack (Stack Alignment).
payload = "pop rdi; ret;" + địa chỉ của "/bin/sh" + "ret;" + địa chỉ của system. 

![stackalignment1](https://github.com/sangnguyenthien/CTF/assets/89742084/c3f3df83-2bd9-41d9-9188-04478c61b11c)


File giải: **solve.py**

Chạy thử local:

![test_local](https://github.com/sangnguyenthien/CTF/assets/89742084/5c45b560-acfb-4fc3-a0f6-46d3e0262a60)

Remote:

![win](https://github.com/sangnguyenthien/CTF/assets/89742084/efef57b9-dcf7-4662-ab9f-fc72f63367df)

