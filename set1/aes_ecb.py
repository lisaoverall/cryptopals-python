#!/usr/bin/env python3

# Cryptopals Set 1 - Challenge 7
# Decrypt AES-128-ECB

import base64
from Crypto.Cipher import AES


def encrypt(pt, key):
    assert len(key) % 16 == 0
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pt)


def decrypt(ct, key):
    assert len(key) % 16 == 0
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ct)


if __name__ == "__main__":
    f = open("7.txt")
    ct_b64 = f.read()
    f.close()

    ct = base64.b64decode(ct_b64) 
    key = b"YELLOW SUBMARINE"
    # print(decrypt(ct, key))
