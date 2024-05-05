lower_512_q = 0xccd9e001ca4397a1a99cdbd971cbfde1a08c3e1609786c932d63e406bfb5b6f5905223e5e9a7e4774217ecb63c5c549bc9f60a348db49d52f22c1347eabe1365

N = 0xcf6ec0443f06791e1ad538f03b4d4c16c10aa17c2f203f715834bcd23d4ca9a388864399f934c96be81ed83a7ba5da9b1b1520186b637f7829d1f7ccd59b1c7814acfab1a27a6bed934d1fdc7ad5900ba506fcfd9c03a1cdd7963c0e5ed49bb1051b2086850aef1ab08090e29803a3eb514a29db09a756de70eb3006ab1f0e7682384b83d75a9cf36248ad039e681fd6683b57b1f9e70ae73d03be759351e6baf14af5643c7dce08e016dc2d6a6d3f3c78393332eec09d04d0b601c929baba111b1e707169d2f900f272e8be44d9bf0c39afa8d9a867a175074dcf3137566b4884019e65364f37b60bd2add12af82f7ba50aab5bfe930a9d6799f5262ca88b23

a = pow(N, 1, pow(2,512))

e = 0x10001

inverse_lower_512_q = pow(lower_512_q, -1, pow(2,512))
lower_512_p = pow(inverse_lower_512_q*a, 1, pow(2,512))


print("Least significant 512 bits of p:", hex(lower_512_p))
#print(len(hex(lower_512_p))-2)

#This actually is p = higher_512_p << 512 + lower_512_p
p = 0xd24b16888265bd8cf656fae2994a7c8972cfb3c4a6d06ef6dc0a5b2386c549a3b0cb205792fffdbc266b0a522cfe8572e22f1b4626d5b8fcf5f8afce3eaff673503f82aa43509fc76b1b123f36a0ee1fc069081729dd62df6de455f2806c1a7a0660e58e04d0b744d7bbf313c26253ea2c0a54072cb1add48f880f53e1a7afe7


q = N//p


phi = (p-1)*(q-1)

d = pow(e,-1,phi)
print(d)

m = input("Enter your message to sign: ")

print("signature: ", pow(int(m), d, N))