s1 = list("eyrnou jngkiaccre af suryot arsto  tdyea rre aouY")


for i in range(0, len(s1)-1, 2):
    temp = s1[i]
    s1[i] = s1[i+1]
    s1[i+1] = temp


for i in range(25):
    temp = s1[i]
    s1[i] = s1[48-i]
    s1[48-i] = temp

print("".join(s1))

# You are ready to start your safe cracking journey
