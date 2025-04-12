from fastecdsa import curve, ecdsa, keys
from fastecdsa.util import RFC6979
from fastecdsa.curve import P256
from hashlib import sha256
import os
from Crypto.Random import random
import string

flag = os.getenv('FLAG', 'ptm{redacted}')

target = b"this_is_something_you_should_not_be_able_to_sign"
ROUNDS = 32

private_key = keys.gen_private_key(curve.P256)
public_key = keys.get_public_key(private_key, curve.P256)
cipher_key = "".join(random.choice(string.printable) for _ in range(8)).encode()

M = [
        [0, 1, 1, 1, 1, 1, 1, 1],
        [1, 0, 0, 0, 0, 0, 1, 1], 
        [1, 0, 0, 0, 0, 1, 0, 1],
        [1, 0, 0, 0, 1, 0, 0, 1],
        [1, 0, 0, 1, 0, 0, 0, 1],
        [1, 0, 1, 0, 0, 0, 0, 1],
        [1, 1, 0, 0, 0, 0, 0, 1],
        [1, 1, 1, 1, 1, 1, 1, 0]
]

S = [84, 193, 27, 152, 147, 232, 233, 40, 43, 24, 184, 97, 100, 81, 200, 187, 1, 54, 114, 175, 72, 119, 172, 223, 214, 77, 133, 2, 251, 142, 53, 250, 137, 242, 103, 88, 87, 128, 38, 17, 22, 215, 210, 161, 160, 33, 255, 104, 60, 183, 123, 236, 192, 15, 182, 197, 157, 78, 8, 59, 225, 148, 65, 116, 166, 213, 126, 163, 135, 0, 212, 79, 5, 50, 241, 132, 76, 115, 57, 246, 47, 28, 153, 226, 96, 85, 229, 36, 194, 177, 180, 109, 25, 154, 86, 195, 69, 112, 204, 3, 12, 63, 188, 207, 62, 181, 121, 238, 235, 158, 145, 66, 26, 219, 99, 92, 216, 171, 34, 21, 253, 106, 162, 35, 91, 140, 131, 248, 52, 245, 173, 146, 90, 61, 240, 205, 149, 18, 198, 93, 125, 164, 29, 124, 179, 110, 111, 4, 11, 136, 68, 209, 32, 67, 218, 227, 230, 41, 143, 186, 44, 167, 107, 252, 156, 75, 64, 39, 203, 10, 170, 159, 7, 102, 243, 202, 58, 89, 82, 129, 239, 120, 176, 49, 221, 224, 117, 30, 130, 189, 19, 220, 37, 234, 73, 42, 211, 70, 138, 9, 14, 101, 190, 139, 98, 191, 231, 222, 16, 151, 95, 196, 55, 80, 249, 56, 201, 244, 168, 113, 150, 169, 118, 23, 185, 134, 83, 48, 228, 217, 141, 94, 20, 127, 208, 31, 51, 178, 122, 237, 45, 74, 155, 174, 71, 144, 206, 247, 6, 199, 108, 13, 254, 105, 165, 46]

S_vec = {}
for n in range(256):
    k = tuple([(n >> (7 - i)) & 1 for i in range(8)])
    assert sum([x << (7 - i)  for i,x in enumerate(k)]) == n
    v = [(S[n] >> (7 - i)) & 1 for i in range(8)]
    assert sum([x << (7 - i)  for i,x in enumerate(v)]) == S[n]
    S_vec[k] = v

round_constants = [pow(3, x, 256) for x in range(ROUNDS)]
round_constants = [[(x >> (7 - i)) & 1 for i in range(8)] for x in round_constants]

def mat_prod(A, B):
    size = len(A)
    result = [[0] * size for _ in range(size)]
    
    for i in range(size):
        for j in range(size):
            result[i][j] = sum(A[i][k] * B[k][j] for k in range(size)) % 2
    
    return result

def encrypt(pt):
    pt_matrix = [[(pt[i] >> (7 - j)) & 1 for j in range(8)] for i in range(8)]
    key_matrix = [[(cipher_key[i] >> (7 - j)) & 1 for j in range(8)] for i in range(8)]

    ct_matrix = [[pt_matrix[__][_] for _ in range(8)] for __ in range(8)]

    for i in range(8):
        for j in range(8):
            ct_matrix[i][j] = ct_matrix[i][j] ^ key_matrix[i][j]
    
    for r in range(ROUNDS):
        new_ct_matrix = [S_vec[tuple(row)][:] for row in ct_matrix]

        for i in range(8):
            new_ct_matrix[i][3] ^= round_constants[r][i]
            new_ct_matrix[i][7] ^= round_constants[r][i]

        new_ct_matrix = mat_prod(M, new_ct_matrix)

        for i in range(8):
            for j in range(8):
                new_ct_matrix[i][j] = new_ct_matrix[i][j] ^ key_matrix[i][j]

        ct_matrix = new_ct_matrix[:]
    
    return bytes([sum([ x << (7 - i)  for i,x in enumerate(row)]) for row in ct_matrix])

def cbc_encrypt(plaintext):
    iv = os.urandom(8)
    ciphertext = b""
    previous = iv
    
    for i in range(0, len(plaintext), 8):
        block = plaintext[i:i+8]

        block_matrix = [[(block[i] >> (7 - j)) & 1 for j in range(8)] for i in range(8)]
        block_matrix = [[block_matrix[j][i] for j in range(8)] for i in range(8)]
        block = bytes([sum([ x << (7 - i)  for i,x in enumerate(row)]) for row in block_matrix])

        xored_block = bytes(b ^ p for b, p in zip(block, previous))
        encrypted_block = encrypt(xored_block)
        ciphertext += encrypted_block
        previous = encrypted_block

    return (iv+ciphertext).hex()

print((public_key.x, public_key.y))

while True:
    to_sign = bytes.fromhex(input("> "))
    if to_sign == target:
        print("nope :)")
    elif to_sign == b"change_key":
        cipher_key = "".join(random.choice(string.printable) for _ in range(8)).encode()
    elif to_sign == b"stop":
        break
    else:
        r, s = ecdsa.sign(to_sign, private_key, hashfunc = sha256)
        nonce = RFC6979(to_sign, private_key, P256.q, sha256).gen_nonce()
        nonce = int.to_bytes(nonce, 32, 'big')
        print("Leak =", cbc_encrypt(nonce))
        print(f'{r = }')
        print(f'{s = }')


r = int(input("r: ").strip())
s = int(input("s: ").strip())

if ecdsa.verify((r, s), target, public_key, hashfunc = sha256):
    print(flag)
else:
    print("nope :(")