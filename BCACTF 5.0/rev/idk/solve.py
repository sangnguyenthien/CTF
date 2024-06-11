import ctypes

v6 = [0 for _ in range(20)]
v6[0] = 466437
v6[1] = 528153
v6[2] = 333852
v6[3] = 530074
v6[4] = 728060
v6[5] = 531211
v6[6] = 400528
v6[7] = 399745
v6[8] = 396035
v6[9] = 530846
v6[10] = 662759
v6[11] = 395326
v6[12] = 397355
v6[13] = 663164
v6[14] = 399371
v6[15] = 532170
v6[16] = 465419
v6[17] = 466482
v6[18] = 532038
v6[19] = 399114




def tzcnt(x):
    if x == 0:
        return 32  # Assuming we're dealing with 32-bit values
    count = 0
    while (x & 1) == 0:
        x >>= 1
        count += 1
    return count

def find_index(v8):
    for i in range(20, len(v8)):
        if v8[i] != 0:
            return i
    return -1



v9 = [0 for _ in range(40)]


plain = [0 for _ in range(40)]

for gnas in range(0, 40, 2):
    print(f"Step {gnas}")
    for first in range(20, 128):
        for second in range(20, 128):
            #print("first: ", first)
        
            #if first == 98 and second == 99:
            #    print("Here")
            #    break
            v9 = [0 for _ in range(40)]
            v9[gnas] = first
            v9[gnas+1] = second

            #v9[2] = ord('a')
            #v9[3] = ord('c')
            #v9[0] = 98
            #v9[1] = 99
            


            v8 = [0 for _ in range(40)]


            for i in range(20):
                v8[i + 20] = (ctypes.c_uint32((0x102040810204081 * ((0x101010101010101 * v9[2 * i + 1]) & 0x8040201008040201)) >> 32).value >> 16) & 0xAAAA | (
                                ctypes.c_uint32((0x102040810204081 * ((0x101010101010101 * v9[2 * i]) & 0x8040201008040201)) >> 32).value >> 17) & 0x5555

            v8[0] = 11
            v8[1] = 19
            v8[2] = 14
            v8[3] = 1
            v8[4] = 3
            v8[5] = 5
            v8[6] = 18
            v8[7] = 13
            v8[8] = 0
            v8[9] = 17
            v8[10] = 6
            v8[11] = 7
            v8[12] = 8
            v8[13] = 16
            v8[14] = 12
            v8[15] = 10
            v8[16] = 4
            v8[17] = 9
            v8[18] = 15
            v8[19] = 2


            #for ( j = 0; j <= 18; j += 2 )                // swap
            for j in range(0, 19, 2):
                v8[v8[j] + 20] ^= v8[v8[j + 1] + 20]
                v8[v8[j + 1] + 20] ^= v8[v8[j] + 20]
                v8[v8[j] + 20] ^= v8[v8[j + 1] + 20]

            #print(v8)


            v7 = [0 for _ in range(20)]
            v7[0] = 18
            v7[1] = 6
            v7[2] = 17
            v7[3] = 4
            v7[4] = 13
            v7[5] = 12
            v7[6] = 10
            v7[7] = 5
            v7[8] = 0
            v7[9] = 14
            v7[10] = 8
            v7[11] = 11
            v7[12] = 16
            v7[13] = 7
            v7[14] = 15
            v7[15] = 1
            v7[16] = 2
            v7[17] = 19
            v7[18] = 9
            v7[19] = 3

            v20 = [int(c, 2) for c in "01 01 00 01 01 01 00 01 00 00".split()[::-1]]
            #print(v20)

            for k in range(0, 19, 2):
                #v20 += v11 << k;
                v11 = v20[k//2]
                v10 = v8[v7[k + 1] + 20] ^ (v8[v7[k + 1] + 20] ^ v8[v7[k] + 20]) & -v11
                v8[v7[k] + 20] ^= -v11 & (v8[v7[k + 1] + 20] ^ v8[v7[k] + 20])
                v8[v7[k + 1] + 20] = v10

            #print(v8)


            #for ( l = 0; l <= 19; ++l )
            for l in range(20):
                v12 = v8[l + 20]
                v12 -= (v12 >> 1) & 0x55555555
                v12 = (v12 & 0x33333333) + ((v12 >> 2) & 0x33333333)
                v12 = (16843009 * (((v12 >> 4) + v12) & 0xF0F0F0F)) >> 24
                v8[l + 20] = ctypes.c_uint32(v8[l + 20]).value >> 1
                v8[l + 20] += v12 << 16


            if v9[4] == ord('t') and v9[5] == ord('h'):
                print(v8)


            #print(v8)
            i_ = find_index(v8)

            '''
            for ( m = 0; m <= 19; ++m )
            {
                for ( n = 0; n < m; ++n )
                {
                v13 = v8[m + 20] | (v8[m + 20] - 1);
                _EAX = v8[m + 20];
                __asm { tzcnt   eax, eax }
                v8[m + 20] = (((~v13 & (unsigned int)(v13 + 1)) - 1) >> (_EAX + 1)) | (v13 + 1);
                }
            }
            '''

            for m in range(20):
                for n in range(m):
                    v13 = v8[m + 20] | (v8[m + 20] - 1)
                    eax = v8[m + 20]
                    eax = tzcnt(eax)
                    v8[m + 20] = (((~v13 & ctypes.c_uint32(v13 + 1).value) - 1) >> (eax + 1)) | (v13 + 1) & 0x000fffff

            #print(v8)
            #print(v8[i_])


            if v9[4] == ord('t') and v9[5] == ord('h'):
                print(v8)
            
            #print(v8)
            #print("index: ", i_)
            if v8[i_] &  0x000fffff == v6[i_-20]:
                print("FOUND")

                plain[gnas] = v9[gnas] 
                plain[gnas+1] = v9[gnas+1]
                print(plain)
                #print(v9[0])
                #print(v9[1])
                print("------")
                break
print("END")
print("".join([chr(num) for num in plain]) + "}")
