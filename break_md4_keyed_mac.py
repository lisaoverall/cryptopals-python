#!/usr/bin/env python3

# Cryptopals Set 4 - Challenge 30
# Break an MD4 keyed MAC using length extension

import md4
import random
from aes_ecb_cbc_oracle import gen_random_bytes

def authenticate_msg(key, msg):
    assert type(key) == bytes
    assert type(msg) == bytes
    
    return md4.MD4().add(key+msg).finish()

def get_md4_padding(msg):
    assert type(msg) == bytes
    return b'\x80' + b'\x00'*((56-(len(msg)+1)%64)%64) + (len(msg)*8).to_bytes(8, 'little')


if __name__ == "__main__":
    k = gen_random_bytes(random.randint(16,32))
    msg = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    mac = authenticate_msg(k, msg)

    # we don't know the key length
    for i in range(16, 32):
        key_placeholder = bytes(i)
        padding = get_md4_padding(key_placeholder + msg)
        new_msg = msg + padding + b';admin=true'

        h = [int.from_bytes(mac[4*i:4*(i+1)], 'little') for i in range(4)]
        md4hash = md4.MD4(count=len(key_placeholder+msg+padding)//64, h=h)
        md4hash.add(b';admin=true')
        new_mac = md4hash.finish()

        if new_mac == authenticate_msg(k, new_msg):
            break

    assert new_mac == authenticate_msg(k, new_msg)
