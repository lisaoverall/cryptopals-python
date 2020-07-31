#!/usr/bin/env python3

from fixed_xor import fixed_xor
from sha1 import Sha1Hash

def hmac_sha1(key, msg):
    assert type(key) == bytes
    assert type(msg) == bytes

    hsh = lambda x: Sha1Hash().update(x).digest()
    blocksize = 64
    
    # Keys longer than blockSize are shortened by hashing them
    if len(key) > blocksize:
        h = hsh(key)  # h is 20 bytes long
        while len(h) < blocksize:
            h += hsh(h + key)
        key = h[:blocksize]  # reduce length to blockSize

    # Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if len(key) < blocksize:
        key += bytes(blocksize-len(key)) 

    o_key_pad = fixed_xor(key, bytes([0x5c] * blocksize))  # Outer padded key
    i_key_pad = fixed_xor(key, bytes([0x36] * blocksize))  # Inner padded key

    return hsh(o_key_pad + hsh(i_key_pad + msg))
