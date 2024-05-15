# Challenge: petshop
## Source: 
> petshop

> ld-2.31.so

> libc-2.31.so

## Solution

Đầu tiên vẫn patch bằng pwninit, chúng ta có được petshop_patched.

Kiểm tra protection:

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/34748cc9-3b96-466c-9cd7-282105b4723e)


----

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/afb47730-f546-4fad-b18c-d7b1a9d378de)

----
Giải thích sơ qua hàm buy():
- pet_list lưu địa chỉ (heap) chứa thông tin danh sách các con vật mà mình sở hữu: địa chỉ lưu tên loại chó/mèo và địa chỉ lưu tên của con vật (cái này do mình đặt). Tổng cộng 0x10 bytes.
- cats và dogs:

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/760f89fb-0f77-4bb6-b489-71bf36e25458)

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/6863a66a-70c4-44e2-a953-292b53164315)

----

- Để ý rằng, chúng ta có 4 types cat/dog. Chúng ta muốn mua type cat/dog nào (từ 1 đến 4) thì input của chúng ta sẽ được lưu ở biến **v6**
- Tức là index của cats và dogs sẽ là [0, 3] (Dòng 14: --v6).
- Như hình dưới đây, chương trình check xem v6 có lớn hơn 3 hay không, nhưng lại không check xem v6 có nhỏ hơn 0 hay không -> chúng ta có thể nhập số âm để leak thông tin, cụ thể là base address
![image](https://github.com/sangnguyenthien/CTF/assets/89742084/615513da-6a5d-467b-9b28-6222e033010c)

- Khi đó, tên type của cat/dog của chúng ta sẽ được lưu thành 1 cái gì đó thay vì là các loại được liệt kê ("Asian", "Siamese", "Scottish Fold")
- Hãy kiểm tra xem có thứ gì hay ho có thể leak ra được không

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/ded667fa-cbd7-44d9-befb-523329ba99e7)

- ở địa chỉ base+0x4008, ngay dưới **cats**, có một con trỏ trỏ vào chính nó (loop) -> có thể leak được code base bằng cách nhập type là một số âm.

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/f2875d03-3ee2-46ce-927a-a7e59c359862)

- 1 cái gì đó lạ lạ, hãy dùng GDB để xem chính xác (đặt breakpoint ở info, dòng printf cho option của **info mine**)

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/ddf58aae-6d1a-4326-a409-479aee565d70)

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/20f52502-e84c-4bf9-a40a-b5aa5a23df25)

Tính toán code base: (code base = leak - 0x4008)

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/ad5c5ba4-5ff5-4c2c-8d7e-defb8cc7f079)

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/1b479ccd-638a-46a5-979a-9546e5b61c92)

Oke, vậy là ngon rồi, đã leak được code base.

----
Bước tiếp theo, hãy xem thử hàm sell()

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/cc827cd8-08fb-425d-8607-3949629a977f)

Ở phần nhập giá trị cho n. Nếu như chúng ta nhập n=1000, và vượt qua được điều kiện if ở dòng 14, 15 (để hàm sell không return "Invalid size") thì chúng ta có thể input tới 1000 kí tự vào s -> overflow.

Phân tích câu lệnh if: vì n chúng ta định nhập vào là to hơn 511 (1000 cho thoải mái) thì vế phải của If  (là n < 0 || n > 511) lúc nào cũng trả về **1**

Suy ra, để vượt qua if, chúng ta cần (unsigned int)__isoc99_scanf("%d", &n) **!= 1** và cụ thể là bằng 0.

scanf() ở câu lệnh if sẽ trả về 0 nếu như bạn nhập kí tự không phải là số. Ví dụ 'a', 'b', 'c',...

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/b0aa73f9-1089-4bcf-8e2b-563c06668abc)


OK vậy là vượt qua được If, nhưng mà làm sao để sử dụng được n=1000 để overflow?.

Đây, chính là cách để chúng ta vừa sử dụng được n=1000 mà vẫn vượt qua được If (gọi sell 2 lần liên tục):

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/8ec52900-c672-4048-961a-b2d78a649bd8)

1000 vẫn còn trên stack, nên khi gọi hàm fgets(s, n, stdin) thì thực chất nó lấy n là [rbp-0x208] (vẫn bằng 1000 = 0x3e8).

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/e9a206cc-02e7-4252-ab29-ac654d616273)


![image](https://github.com/sangnguyenthien/CTF/assets/89742084/d62d260f-c41f-4685-9683-92e25bded889)

----
Việc còn lại là viết rop chain để leak GOT -> leak libc, nhảy về hàm main. Sau đó lại tận dụng buffer overflow này để ret2libc.

Code giải: **solve.py**
Note: Rop chain mình viết có hơi ngáo một chút ở chỗ nhảy về main :)). Bạn có thể thay thế bằng cách thêm ngay địa chỉ hàm main vào ngay sau puts plt (leak GOT) để sau khi leak được địa chỉ libc thì chúng ta lại quay về hàm main.
