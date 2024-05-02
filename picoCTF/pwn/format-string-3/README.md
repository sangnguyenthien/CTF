# Challenge: format string 3

## Description
![image](https://github.com/sangnguyenthien/CTF/assets/89742084/39ed08c0-9158-45e3-9751-9fb21a03dd96)

## Solution

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/86ce584d-fe26-4856-ab1c-59ce0a8d5a61)

Dòng 15 leak cho ta địa chỉ setvbuf -> leak địa chỉ libc
Dòng 26 có lỗi format string
Dòng 28 thì puts("/bin/sh")
No PIE
--> Có thể dùng format string để ghi đè GOT entry của **puts** với địa chỉ của **system** trong libc. Thì khi thực thi dòng 28 thì thay vì **puts("/bin/sh")** thì thực tế sẽ là **system("/bin/sh")**

Code giải: **exploit.py**
