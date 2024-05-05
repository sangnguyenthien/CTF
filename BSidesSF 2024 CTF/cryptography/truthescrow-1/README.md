

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/4547f375-c679-417b-81fc-c79b55169779)

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/030af642-2fab-412e-93b2-87b02d029e27)

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/2e03aaad-0b98-4e03-a9e9-146c1990cc6d)

> N mod 2^512 = ((p mod 2^512) * (q mod 2^512)) mod 2^512 = ((512 lower bits of p) * (512 lower bits of q)) mod 2^512

-------------------
We have:
-> least significant 512 bits of q: KNOWN
-> most significant 512 bits of p: KNOWN
-> N: KNOWN

Then, we can leak the least significant 512 bits of p -> Most significant 512 bits of p and Least significant 512 bits of p -> p
From p, calculate q = N//p and calculate the private key **d** = e^-1 mod phi(N)

Here, i want to read the truth of Citizen 0 (Nicholas Howgrave-Graham). Then I must provide the valid signature for some random message **m** to authenticate.

Create signature by calculating **s** = m^d mod N

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/79a25ca6-0121-49bc-8108-3f38d49acc26)


Solution: **solve_p_q.py**
![image](https://github.com/sangnguyenthien/CTF/assets/89742084/00061f35-b230-481f-993c-675cea23a1c7)

![image](https://github.com/sangnguyenthien/CTF/assets/89742084/5212077e-6edb-430a-91b1-cf180392a55c)
