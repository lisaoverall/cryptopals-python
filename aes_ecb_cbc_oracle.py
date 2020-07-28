#!/usr/bin/env python3

# Cryptopals Set 2 - Challenge 11
# ECB/CBC detection oracle
# Detect the block cipher mode the function is using each time. 

import random
import pkcs7
import aes_ecb
import aes_cbc

def gen_random_bytes(length):
    return bytes([random.randint(0, 255) for i in range(length)])

def gen_random_aes_key():
    """Generate a random AES key, i.e. 16 random bytes."""
    return gen_random_bytes(16)

def random_encrypt(pt):
    "Generate a random key and encrypt under it."

    key = gen_random_aes_key()
    
    # append 5-10 bytes (count chosen randomly) before the plaintext
    # and 5-10 bytes after the plaintext.
    random_pad_before = gen_random_bytes(random.randint(5, 10))
    random_pad_after = gen_random_bytes(random.randint(5, 10))
    pt = random_pad_before + pt + random_pad_after
    
    # choose to encrypt under ECB 1/2 the time, and under CBC the other half
    # (just use random IVs each time for CBC).
    enc_func = random.choice([aes_ecb.encrypt, aes_cbc.encrypt])
    if enc_func == aes_ecb.encrypt:
        mode = 'ECB'
        pt = pkcs7.pad_for_aes(pt)
        ct = aes_ecb.encrypt(pt, key)
    else:
        mode = 'CBC'
        ct = aes_cbc.encrypt(pt, key, gen_random_bytes(16))
    return mode, ct


def aes_oracle(pt):
    mode, ct = random_encrypt(pt)
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    if len(set(blocks)) != len(blocks):
        guess = 'ECB'
    else:
        guess = 'CBC'
    return guess, mode


if __name__ == "__main__":
    # fiddled around with pt being strings of random bytes,
    # but poor oracle results: wrong guesses were always CBC for ECB.
    # This is because, with an alphabet of 256 possible values,
    # low probability to get two 16-byte blocks that are the same
    # (would need a LOT of ciphertext)
    
    pt = bytes(10*16)
    
    for i in range(1000):  # run 1000 tests
        guess, mode = aes_oracle(pt)
        try:
            assert guess == mode
        except:
            print(f"{i}: mode={mode}, guess={guess}, pt_len={len(pt)}")
        



