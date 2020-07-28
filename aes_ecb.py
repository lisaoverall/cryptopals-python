#!/usr/bin/env python3

# Cryptopals Set 1 - Challenge 7
# Decrypt AES-128-ECB

import base64
from Crypto.Cipher import AES
import pkcs7

def encrypt(pt, key):
    assert len(pt) % 16 == 0
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pt)


def decrypt(ct, key):
    assert len(ct) % 16 == 0
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ct)

if __name__ == "__main__":
    f = open("challenge-data/7.txt")
    ct_b64 = f.read()
    f.close()

    ct = base64.b64decode(ct_b64) 
    key = b"YELLOW SUBMARINE"
    pt = pkcs7.unpad(decrypt(ct, key))
    # print(pt)

    ct_len = ((len(pt) // 16) + (len(pt) % 16 != 0)) * 16
    assert ct_len == len(ct)
    if len(pt) == ct_len:
        pt += pkcs7.pad(b'', 16)
    else:
        pt = pt[:-(len(pt) % 16)] + pkcs7.pad(pt[-(len(pt) % 16):], 16)
    assert len(pt) % 16 == 0
    
    assert encrypt(decrypt(ct, key), key) == ct
