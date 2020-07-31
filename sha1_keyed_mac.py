#!/usr/bin/env python3

# Cryptopals Set 4 - Challenge 28
# Implement a SHA-1 keyed MAC

from sha1 import Sha1Hash
from aes_ecb_cbc_oracle import gen_random_aes_key

# Write a function to authenticate a message under a secret key by using a secret-prefix MAC, which is simply:
# SHA1(key || message)
# Verify that you cannot tamper with the message without breaking the MAC you've produced, and that you can't produce a new MAC without knowing the secret key.

def authenticate_msg(key, msg):
    assert type(key) == bytes
    assert type(msg) == bytes

    h = Sha1Hash()
    h.update(key + msg)
    return h.digest()

if __name__ == "__main__":
    k = gen_random_aes_key()
    m1 = b'foo'
    m2 = b'bar'
    assert authenticate_msg(k, m1) != authenticate_msg(k, m2)
