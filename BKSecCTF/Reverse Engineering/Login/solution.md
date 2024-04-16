# Challenge: Login
## Description

> ""

## Source
> chall (2)
## Solution
First, try to analyze and view the pseudocode using IDA (Interactive Disassembler)

I have changed the variable names for readability

### Explanation
```
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string<std::allocator<char>>(
    enc_username,
    "0915987514_$$010750_so$dt@$ksec_Spid3$_HUST-ph1she$_team_Chu$g_t0i_l@_H@cK3$",
    &v13);
  std::allocator<char>::~allocator(&v13);
  std::allocator<char>::allocator(&v13);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string<std::allocator<char>>(
    enc_password,
    "SPIDER=human, !robot",
    &v13);
  std::allocator<char>::~allocator(&v13);
```
> In short, this code does:
```
enc_username = "0915987514_$$010750_so$dt@$ksec_Spid3$_HUST-ph1she$_team_Chu$g_t0i_l@_H@cK3$";
enc_password = "SPIDER=human, !robot";
```
---
```
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    "Welcome to BKSEC, User! Please choose 1 option\n1. Login\n2. Spid3r-decode\nchoose> ");
  std::istream::operator>>(&std::cin, &v13);
```
> The server will ask us for input 1 (Login) or 2 (Spid3r decode?) and store our choice in **v13**
---
```
if ( v13 == 1 )
  {
    std::operator<<<std::char_traits<char>>(
      &std::cout,
      "----------------------------------------------\n"
      "Login CLI - Robot Verify\n"
      "---------------------------------------------- \n"
      "Username: ");
    std::operator>><char>(&std::cin, username);
    std::operator<<<std::char_traits<char>>(&std::cout, "Password: ");
    std::operator>><char>(&std::cin, password);
```
> If our choice is 1, the server will ask us to input **username** and **password**
---
```
    hashu((__int64)v20, (__int64)username);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator=(username, v20);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v20);
    
    hashp(v21, password);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator=(password, v21);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v21);
    
    if ( (unsigned __int8)std::operator==<char>(username, enc_username)
      && (unsigned __int8)std::operator==<char>(password, enc_password) )
    {
      std::operator<<<std::char_traits<char>>(&std::cout, "\nCorrect Username & Password! Robot Confirm...\n");
      std::ifstream::basic_ifstream(v21, "flag.txt", 8LL);
```
>We can see that the **hashu()** and **hashp()** did something with the **username** and **password** (encryption or smth). Then compare with **enc_username** and **enc_password**, if they **match** then we'll probably get something in **flag.txt**. ^^

---

    hashu((__int64)v20, (__int64)username);
   
   ```
   __int64 __fastcall hashu(__int64 a1, __int64 a2)
{
  int v2; // ebx
  int i; // [rsp+1Ch] [rbp-14h]

  for ( i = 0;
        i < (unsigned __int64)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size(a2);
        ++i )
  {
    if ( (*(_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](a2, i) & 1) != 0 )
      v2 = 2
         * (*(char *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](a2, i) + 1);
    else
      LOBYTE(v2) = *(_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](
                               a2,
                               i)
                 + 1;
    *(_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](a2, i) = v2;
  }
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(a1, a2);
  return a1;
}
   ```
> In short, hashu() does (in Python):
```
#hashu()
for i in range(len(username)):
	if username[i] % 2 == 0:
		username = 2*(username[i]+1)
	else:
		username = username + 1
```
---

    hashp(v21, password);
  
  ```
  __int64 __fastcall hashp(__int64 a1, __int64 a2)
{
  char v2; // bl
  __int64 v3; // rax
  char v4; // bl
  int i; // [rsp+1Ch] [rbp-14h]

  for ( i = 0;
        i < (unsigned __int64)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size(a2);
        ++i )
  {
    v2 = *(_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](a2, i) + i;
    v3 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size(a2);
    v4 = (v2 ^ *(_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](
                           a2,
                           v3 - i - 1))
       + 3;
    *(_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](a2, i) = v4;
  }
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(a1, a2);
  return a1;
}
  ```
> In short, hashp() does (in Python):
```
#hashp()
for i in range(len(password)):
	password[i] = (password[i] + i) ^ password[len(password)-i-1] + 3
```
---
Here is the flow
> correct username ----------> hashu() ----------> enc_username = "0915987514_$$010..."
> correct password ----------> hashp() ----------> enc_password = "SPIDER=..."

To retrieve correct_username and correct_password we need to write the inverse function of hashu() and hashp()
```
enc_username = "0915987514_$$010750_so$dt@$ksec_Spid3$_HUST-ph1she$_team_Chu$g_t0i_l@_H@cK3$"

enc_password = "SPIDER=human, !robot"

  
  
  

######## For username
enc_username = [ord(c) for  c  in  enc_username]
username = [0  for  _  in  range(len(enc_username))]

for  i  in  range(len(username)):
	if  enc_username[i] % 2 == 0:
		username[i] = enc_username[i]//2-1
	else:
		username[i] = enc_username[i]-1
str_username = "".join([chr(n) for  n  in  username])
print(str_username.encode())
########

######## For password
enc_password = [ord(c) for  c  in  enc_password]
password = [0  for  _  in  range(len(enc_password))]
#print(enc_password)

for i in range(10):
	#test for pass[i]
	for  test  in  range(32, 128):
		test_pass_remain = (enc_password[i]-3)^(test+i)
		#pass[19-i] = test_pass_remain
		if (((test_pass_remain+19-i)^enc_password[i]) + 3) == enc_password[20-i-1]:
			password[i] = test
			password[20-i-1] = test_pass_remain
			break
str_password = "".join([chr(n) for  n  in  password])
print(str_password.encode())
########
```
After get the correct username and correct password, let's try
```
from  pwn  import *

  

p = remote("128.199.219.160", 4000)

p.sendlineafter(b"Welcome to BKSEC, User! Please choose 1 option\n1. Login\n2. Spid3r-decode\nchoose> ", b"1")
  
username = b'\x178048\x1b640\x19^\x11\x11\x170\x1764\x17^rn\x1119\x1f\x11jrdb^R7h12\x11^#TR),730r3d\x11^9d`l^B3t\x11f^9\x17h^5\x1f^#\x1fbJ2\x11'
p.sendlineafter(b"Username: ", username)

password = b'_fAVUl#IY:)\x135\x13>\x1b\x18\x05*\x0f'
p.sendlineafter(b"Password: ", password)

p.interactive()
```
Hmm, the server returns a flag that is probably encoded...How to decode? --> Try Spid3r-decode (Option 2) to decode!
GOT IT!

> BKSEC{Oh!_y0u\are_th3_re@l_rev3rs3r!}

