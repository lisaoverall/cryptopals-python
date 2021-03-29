#!/usr/bin/env python3

# Cryptopals Set 4 - Challenge 27

# Take your code from the CBC exercise and modify it so that it repurposes the key for CBC encryption as the IV.

from aes_ecb_cbc_oracle import gen_random_aes_key
import aes_cbc
import pkcs7
from fixed_xor import fixed_xor
import re

KEY = gen_random_aes_key()
PREFIX = b"comment1=cooking%20MCs;userdata="  # len = 32
SUFFIX = b";comment2=%20like%20a%20pound%20of%20bacon"

# need this to be able to programmatically extract pt(')
class NonAsciiError(Exception):
    def __init__(self, expression, message):
        self.expression = expression
        self.message = message
        
def insert_user_data(s):
    assert type(s) == bytes
    for b in s:
        if b > 127:
            raise NonAsciiError(s, "User data cannot contain non-ASCII chars")
    # is this what it means to quote out a character?
    # should I be URL encoding?
    s = re.sub(b';', b'\\;', s)
    s = re.sub(b'=', b'\\=', s)
    pt = pkcs7.pad_for_aes(PREFIX + s + SUFFIX)
    return aes_cbc.encrypt(pt, KEY, KEY)

def decrypt_and_check(s):
    assert type(s) == bytes
    pt = pkcs7.unpad(aes_cbc.decrypt(s, KEY, KEY))
    for b in pt:
        if b > 127:
            raise NonAsciiError(pt, "Non-ASCII characters found")
    return b";admin=true;" in pt


if __name__ == "__main__":
    s = b'asdf'
    t = b';admin=true'
    assert pkcs7.unpad(aes_cbc.decrypt(insert_user_data(s), KEY, KEY)) == (PREFIX + s + SUFFIX)

    # Use your code to encrypt a message that is at least 3 blocks long:
    # AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
    s = b'A'*16 + b'B'*16 + b'C'*16
    ct = insert_user_data(s)

    # Modify the message (you are now the attacker):
    # C_1, C_2, C_3 -> C_1, 0, C_1
    # include end so no padding error
    new_ct = ct[:16] + bytes(16) + ct[:16] + ct[3*16:]  
    
    # Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found.
    try:
        decrypt_and_check(new_ct)
    except NonAsciiError as err:
        pt = err.expression
        pass
        
    # As the attacker, recovering the plaintext from the error, extract the key:
    # P'_1 XOR P'_3

    k = fixed_xor(pt[:16], pt[2*16:3*16])
    assert k == KEY
