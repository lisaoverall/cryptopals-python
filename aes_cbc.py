#!/usr/bin/env python3

# Cryptopals Set 2 - Challenge 10
# Implement AES CBC
# take ECB function, make it encrypt instead of decrypt, and
# use XOR function to combine

import base64
from fixed_xor import fixed_xor
import aes_ecb
import pkcs7


def encrypt(pt, key, iv):
    assert len(pt) % 16 == 0
    assert len(key) == 16
    assert len(iv) == 16

    ct = bytearray(len(pt) + 16)
    ct[0:16] = iv
    for i in range(0, len(pt), 16):
        ct[i+16:i+32] = aes_ecb.encrypt(fixed_xor(pt[i:i+16], ct[i:i+16]), key)
    return bytes(ct[16:])


def decrypt(ct, key, iv):
    assert len(ct) % 16 == 0
    assert len(key) % 16 == 0
    assert len(iv) == 16
    ivs = iv + ct
    pt_padded = bytearray(len(ct))
    for i in range(0, len(ct), 16):
        pt_padded[i:i+16] = fixed_xor(aes_ecb.decrypt(ct[i:i+16], key), ivs[i:i+16])
    return bytes(pt_padded)
        
if __name__ == '__main__':
    key = b"YELLOW SUBMARINE"
    iv = bytes(16)
    
    assert len(encrypt(pkcs7.pad_for_aes(b''), key, iv)) == 16
    assert len(encrypt(pkcs7.pad_for_aes(b'a'*15), key, iv)) == 16
    assert len(encrypt(pkcs7.pad_for_aes(b'a'*16), key, iv)) == 32
    assert pkcs7.unpad(decrypt(encrypt(pkcs7.pad_for_aes(b''), key, iv), key, iv)) == b''
    assert pkcs7.unpad(decrypt(encrypt(pkcs7.pad_for_aes(b'a'*15), key, iv), key, iv)) == b'a'*15
    assert pkcs7.unpad(decrypt(encrypt(pkcs7.pad_for_aes(b'a'*16), key, iv), key, iv)) == b'a'*16
    
    
    f = open("challenge-data/10.txt")
    ct_b64 = f.read()
    f.close()
    ct = base64.b64decode(ct_b64)
    
    
    res = pkcs7.unpad(decrypt(ct, key, iv))
    # print(res)
