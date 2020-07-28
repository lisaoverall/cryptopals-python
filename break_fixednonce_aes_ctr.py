#!/usr/bin/env python3

# Cryptopals Set 3 - Challenge 19 / 20
# Break fixed-nonce CTR mode

# Because the CTR nonce wasn't randomized for each encryption,
# each ciphertext has been encrypted against the same keystream. This is very bad.

# CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE
# And since the keystream is the same for every ciphertext:
# CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE
# (attack is very similar to repeated key xor)

import base64
from functools import reduce
import math
from operator import add
import string
from aes_ecb_cbc_oracle import gen_random_aes_key
from aes_ctr import AESCTR
from single_byte_xor import score
from fixed_xor import fixed_xor

# Generate a random AES key.
KEY = gen_random_aes_key()

def get_keystream(cts):
    # challenge designers suggest using shortest ct for ks len
    kslen = max(len(ct) for ct in cts)
    
    keystream = bytes()
    for i in range(kslen):
        transpose = reduce(add, [ct[i:i+1] for ct in cts])
        max_score = 0
        putative_key_byte = None
        for c in range(256):
            putative_pt = fixed_xor(transpose, bytes([c]*len(transpose)))
            thisscore = score(putative_pt)
            
            if thisscore > max_score:
                max_score = thisscore
                putative_key_byte = c

        keystream += bytes([putative_key_byte])

    return keystream


if __name__ == "__main__":
    
    # In successive encryptions (not in one big running CTR stream), encrypt each line of the base64 decodes of the following, producing multiple independent ciphertexts:
    f = open("challenge-data/19.txt")
    pts = [base64.b64decode(x.strip()) for x in f.readlines()]
    assert len(pts) == 40
    f.close()

    # nonce value fixed to 0
    # In successive encryptions (not in one big running CTR stream), encrypt:
    cts = [AESCTR(KEY).crypt(pt) for pt in pts]
    assert len(cts) == len(pts)

    keystream = get_keystream(cts)

    # manually inspect decrypts
    # for i in range(len(cts)):
    #     ct = cts[i]
    #     putative_pt = fixed_xor(ct, keystream[:len(ct)])
    #     if putative_pt != pts[i]:
    #         print(f"[{i}, len={len(putative_pt)}]: {putative_pt} // {pts[i]}")

    # need to fix up the keystream a little, due to the silly scoring function
    # googling, we see these are lines from a Yeats Poem
    # https://www.poetryfoundation.org/poems/43289/easter-1916
    len_cts = [len(ct) for ct in cts]
    longest_ct = cts[len_cts.index(max(len_cts))]
    putative_longest_pt = fixed_xor(longest_ct, keystream[:len(longest_ct)])
    # print(putative_longest_pt)  # manually inspect
    actual_longest_pt = b'He, too, has been changed in his turn,'
    actual_keystream = fixed_xor(longest_ct, actual_longest_pt)

    for i in range(len(cts)):
        ct = cts[i]
        putative_pt = fixed_xor(ct, actual_keystream[:len(ct)])
        assert putative_pt == pts[i]

    f = open('challenge-data/20.txt')
    pts = [base64.b64decode(x.strip()) for x in f.readlines()]
    f.close()

    # nonce value fixed to 0
    # In successive encryptions (not in one big running CTR stream), encrypt:
    cts = [AESCTR(KEY).crypt(pt) for pt in pts]
    assert len(cts) == len(pts)

    keystream = get_keystream(cts)

    # manually inspect decrypts
    # for i in range(len(cts)):
    #     ct = cts[i]
    #     putative_pt = fixed_xor(ct, keystream[:len(ct)])
    #     if putative_pt != pts[i]:
    #         print(f"[{i}, len={len(putative_pt)}]: {putative_pt} // {pts[i]}")

    # we do pretty well, but let's fix up the keystream
    len_cts = [len(ct) for ct in cts]
    longest_ct = cts[len_cts.index(max(len_cts))]
    putative_longest_pt = fixed_xor(longest_ct, keystream[:len(longest_ct)])
    # print(putative_longest_pt)  # manually inspect
    actual_longest_pt = b'You want to hear some sounds that not only pounds but please your eardrums; / I sit back and observe the whole scenery'
    actual_keystream = fixed_xor(longest_ct, actual_longest_pt)

    for i in range(len(cts)):
        ct = cts[i]
        putative_pt = fixed_xor(ct, actual_keystream[:len(ct)])
        assert putative_pt == pts[i]
