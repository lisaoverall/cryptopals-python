#!/usr/bin/env python3

# Cryptopals Set 4 - Challenge 25
# Break random-access read/write AES-CTR

import base64
from aes_ctr import AESCTR
import aes_ecb
from aes_ecb_cbc_oracle import gen_random_aes_key
from fixed_xor import fixed_xor

KEY = gen_random_aes_key()

if __name__ == "__main__":
    f = open("challenge-data/25.txt")
    ct_b64 = f.read()
    f.close()
    ct = base64.b64decode(ct_b64)
    pt = aes_ecb.decrypt(ct, b'YELLOW SUBMARINE')
    
    ctr = AESCTR(KEY)
    ct = ctr.crypt(pt)

    # encrypting null bytes returns keystream
    k = ctr.edit(ct, 0, bytes(len(ct)))
    assert fixed_xor(ct, k) == pt
