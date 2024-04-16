# Challenge: ArrProXD
## Description

> "wee-wuh"

## Source

> abc
## Solution
First, I will use **HxD** to view the hexdump of **abc** using on Windows.
![hexdump](https://github.com/sangnguyenthien/CTF/blob/main/BKSecCTF/Reverse%20Engineering/ArrProXD/hexdump.PNG)
It looks so strange... What is this??
But from the **description**, I found something quite interesting...
[Uiua: A stack-based array programming language](https://www.uiua.org/)

GOT IT! This is exactly what we are looking for. But..
Bro, this programming language has a syntax like hieroglyphs :))
Here is the source code:
```
# Let's start programming
N ← &sc
◌+1◌.N
F ← -@\0 N

A ← ⊢↯3_13F
+4⇡⧻.A
◿2+∵(⇌⬚0↙8⋯):∵(⇌⬚0↙8⋯)
P ← [.......2]
≡(×⇌ⁿ⇡8P)
/+⍉
≍70_78_85_66_75_114_94_99_61_126_81_99_36
⍤"Sorry, pls try again 😔"

≡(↻4)∵(⇌⬚0↙8⋯)↘13F
O ← 2_2_2_2_2_2_2_2
≡(×⇌ⁿ⇡8◌.O)
/+⍉230_118_87_22_118_51_245_19_55_245_102_87_230_245_19_83_230_69_245_19_71_245_4_4_243_215
≍
⍤"So close, just one more step to heaven"
"Go and summit the 🚩"
```
### Explanation
First, this program will ask the user to enter a string
```
N ← &sc
◌+1◌.N
F ← -@\0 N
```
Since 2 lines
```
≍70_78_85_66_75_114_94_99_61_126_81_99_36
/+⍉230_118_87_22_118_51_245_19_55_245_102_87_230_245_19_83_230_69_245_19_71_245_4_4_243_215
```
I guess the length of the flag is 13+27 = 40.

Move to the next part, how the input string is encoded?
> First 13 characters of INPUT will be encrypted:
> XOR 1st character with 4, 2nd character with 5, 3rd with 6,...
```
A ← ⊢↯3_13F
+4⇡⧻.A
◿2+∵(⇌⬚0↙8⋯):∵(⇌⬚0↙8⋯)
P ← [.......2]
≡(×⇌ⁿ⇡8P)
/+⍉

#This line will check if the ciphertext matches the below array. If not, #the program will print "Sorry, pls try again"
≍70_78_85_66_75_114_94_99_61_126_81_99_36
⍤"Sorry, pls try again 😔"
```
> Decoding this array of length 13:
> BKSEC{Th1s_l4

We're on the right track, this is the first part of the **flag**.

This is what the program does with the rest of the flag.
```
≡(↻4)∵(⇌⬚0↙8⋯)↘13F
O ← 2_2_2_2_2_2_2_2
≡(×⇌ⁿ⇡8◌.O)
/+⍉230_118_87_22_118_51_245_19_55_245_102_87_230_245_19_83_230_69_245_19_71_245_4_4_243_215
≍
⍤"So close, just one more step to heaven"
"Go and summit the 🚩"
```
> After reading the syntax of uiua, I understood that the first line will rotate 4 bits of the elements in the array (each element is 8 bits) (the rest of the flag, meaning the array will have 26 elements). For example 0110 0001 will become 0001 0110.
> And check if the ciphertext matches the below array (26 elements)...
> To decrypt, just rotate 4 bits (rotating left is the same as right in this case)

**ALL DONE**
```
arr = [70,78,85,66,75,114,94,99,61,126,81,99,36]
start = 4
result = [20  for  _  in  range(len(arr))]
for  i  in  range(len(arr)):
	result[i] = arr[i] ^ start
	start += 1
print("".join([chr(c) for  c  in  result]),end="") 

low = [int(i) for  i  in  "230_118_87_22_118_51_245_19_55_245_102_87_230_245_19_83_230_69_245_19_71_245_4_4_243_215".split("_")]
def  rotate(n):
	return ((n & 0b1111) << 4)|(n >> 4)
for  c  in  low:
print(chr(rotate(c)),end="")
#BKSEC{Th1s_l4nguag3_1s_fun_15nT_1t_@@?}
```
