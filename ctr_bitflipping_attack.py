#!/usr/bin/env python3

# Cryptopals Set 4 - Challenge 26
# Re-implement the CBC bitflipping exercise from earlier to use CTR mode instead of CBC mode. Inject an "admin=true" token.

from aes_ctr import AESCTR
from aes_ecb_cbc_oracle import gen_random_aes_key
from fixed_xor import fixed_xor
import re


KEY = gen_random_aes_key()
PREFIX = b"comment1=cooking%20MCs;userdata="  # len = 32
SUFFIX = b";comment2=%20like%20a%20pound%20of%20bacon"

def insert_user_data(s):
    # is this what it means to quote out a character?
    # should I be URL encoding?
    s = re.sub(b';', b'\\;', s)
    s = re.sub(b'=', b'\\=', s)
    pt = PREFIX + s + SUFFIX

    ctr = AESCTR(KEY)
    return ctr.crypt(pt)

def decrypt_and_check(s):
    ctr = AESCTR(KEY)
    pt = ctr.crypt(s)
    return b";admin=true;" in pt

if __name__ == "__main__":
    s = b'asdf'
    t = b';admin=true'

    ctr = AESCTR(KEY)
    assert ctr.crypt(insert_user_data(s)) == (PREFIX + s + SUFFIX)
    ctr = AESCTR(KEY)
    assert decrypt_and_check(ctr.crypt(PREFIX+ s + t + SUFFIX))
    ctr = AESCTR(KEY)
    assert not decrypt_and_check(ctr.crypt(t))

    # modify user data block so that
    # there are nulls the length of the target insertion
    # so we can recover that part of the keystream
    target = b";admin=true"
    submit = b'A' * (16 - len(target)) + bytes(len(target))
    ct = insert_user_data(submit)
    k = ct[len(PREFIX) + 16 - len(target): len(PREFIX) + 16] 
    new_ct = ct[:len(PREFIX) + 16 - len(target)] + fixed_xor(target, k) + ct[len(PREFIX) + 16:] 
    
    assert decrypt_and_check(new_ct)
