#!/usr/bin/env python3

# Cryptopals Set 3 - Challenge 24
# Create the MT19937 stream cipher and break it

import random
import string
import time
from mt19937 import MT19937 
from fixed_xor import fixed_xor
from aes_ecb_cbc_oracle import gen_random_bytes

# You can create a trivial stream cipher out of any PRNG; use it to generate a sequence of 8 bit outputs and call those outputs a keystream. XOR each byte of plaintext with each successive byte of keystream.

# Write the function that does this for MT19937 using a 16-bit seed. Verify that you can encrypt and decrypt properly. This code should look similar to your CTR code.

class MT19937StreamCipher:
    def __init__(self, seed):
        assert seed < 2**16  # 16-bit seed

        self.rng = MT19937()
        self.rng.seed(seed)
        self.__keystream = bytes()

    def __grow_keystream(self):
        # each output of rand method is 32 bits
        # so we grow the keystream by 4 bytes each time;
        # integers are big-endian in Python
        self.__keystream += self.rng.rand().to_bytes(4, 'big')

    def crypt(self, bs):
        assert type(bs) == bytes
        while len(self.__keystream) < len(bs):
            self.__grow_keystream()

        k = self.__keystream[:len(bs)]

        self.__keystream = self.__keystream[len(bs):]

        return fixed_xor(k, bs)

# Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time.

def check_token(tok):
    rng = MT19937()
    rng.seed(int(time.time()))

    t = b''
    while len(t) < len(tok):
        t += rng.rand().to_bytes(4, 'big')

    return t[:len(tok)] == tok
    

if __name__ == "__main__":
    pt = b'foobarbazbiz'
    mtsc = MT19937StreamCipher(37)
    ct = mtsc.crypt(pt)

    mtsc = MT19937StreamCipher(37)
    res = mtsc.crypt(ct)
    assert res == pt
    
    # Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters) prefixed by a random number of random characters.
    pt = bytes(''.join([random.choice(string.printable) for i in range(random.randint(5,10))]), 'ascii')
    pt += b'A'*14
    s = random.randint(0, 2**16 - 1)
    mtsc = MT19937StreamCipher(s)
    ct = mtsc.crypt(pt)
    
    # From the ciphertext, recover the "key" (the 16 bit seed).
    # 16-bit exhaust
    rng = MT19937()
    for i in range(2**16):
        rng.seed(i)
        keystream = bytes()
        while len(keystream) < len(ct):
            keystream += rng.rand().to_bytes(4, 'big')
        pt = fixed_xor(ct, keystream[:len(ct)])
        if pt[-14:] == b'A'*14:
            assert i == s
            break

    # Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.
    rng = MT19937()
    rng.seed(int(time.time()))
    token = bytes()
    for i in range(4):
        token += rng.rand().to_bytes(4, 'big')
    
    assert check_token(token)
    
