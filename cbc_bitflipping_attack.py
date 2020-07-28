#!/usr/bin/env python3

# Cryptopals Set 2 - Challenge 16
# If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.

# Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

# You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:
  # - completely scrambles the block the error occurs in
  # - Produces the identical 1-bit error(/edit) in the next ciphertext block.

from aes_ecb_cbc_oracle import gen_random_aes_key
import aes_cbc
import pkcs7
import re

KEY = gen_random_aes_key()
PREFIX = b"comment1=cooking%20MCs;userdata="  # len = 32
SUFFIX = b";comment2=%20like%20a%20pound%20of%20bacon"
    
def insert_user_data(s):
    # is this what it means to quote out a character?
    # should I be URL encoding?
    s = re.sub(b';', b'\\;', s)
    s = re.sub(b'=', b'\\=', s)
    iv = bytes(16)
    pt = pkcs7.pad_for_aes(PREFIX + s + SUFFIX)
    return aes_cbc.encrypt(pt, KEY, iv)

def decrypt_and_check(s):
    iv = bytes(16)
    pt = aes_cbc.decrypt(s, KEY, iv)
    return b";admin=true;" in pt
 

if __name__ == "__main__":
    s = b'asdf'
    t = b';admin=true'
    assert pkcs7.unpad(aes_cbc.decrypt(insert_user_data(s), KEY, bytes(16))) == (PREFIX + s + SUFFIX)
    assert decrypt_and_check(aes_cbc.encrypt(pkcs7.pad_for_aes(PREFIX+ s + t + SUFFIX), KEY, bytes(16)))
    assert not decrypt_and_check(aes_cbc.encrypt(pkcs7.pad_for_aes(t), KEY, bytes(16)))

    # PREFIX len is 32 - modify 2nd block so that
    # error causes ";admin=true" to appear in user data
    target = b";admin=true"
    submit = b"allsafedata"
    assert len(target) == len(submit)
    k = len(submit)

    # calculate distance between strings by bytewise xor
    dist = [x ^ y for x, y in zip(target, submit)]

    ct = insert_user_data(submit)
    new_ct = ct[:16] + bytes(x ^ y for x, y in zip(ct[16:16+k], dist)) + ct[16+k:]

    assert decrypt_and_check(new_ct)
