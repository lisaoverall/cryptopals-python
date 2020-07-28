#!/usr/bin/env python3

# Cryptopals Set 3 - Challenge 17
# This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications; the second function models the server's consumption of an encrypted session token, as if it was a cookie.

# It turns out that it's possible to decrypt the ciphertexts provided by the first function.

# The decryption here depends on a side-channel leak by the decryption function. The leak is the error message that the padding is valid or not.

# The fundamental insight behind this attack is that the byte 01h is valid padding, and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.

# 02h in isolation is not valid padding.

# 02h 02h is valid padding, but is much less likely to occur randomly than 01h.

# 03h 03h 03h is even less likely.

# So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.

# It is easy to get tripped up on the fact that CBC plaintexts are "padded". Padding oracles have nothing to do with the actual padding on a CBC plaintext. It's an attack that targets a specific bit of code that handles decryption. You can mount a padding oracle on any CBC block, whether it's padded or not.

from aes_ecb_cbc_oracle import gen_random_aes_key
import aes_cbc
import pkcs7
from fixed_xor import fixed_xor
import random
import base64

KEY = gen_random_aes_key()

def encrypt_random_string():

    ss = [
        b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
    ]

    s = base64.b64decode(random.choice(ss))
    iv = gen_random_aes_key()
    return (aes_cbc.encrypt(pkcs7.pad_for_aes(s), KEY, iv), iv)

def padding_oracle(ct, iv):
    pt = aes_cbc.decrypt(ct, KEY, iv)
    return pkcs7.is_padded(pt)


if __name__ == "__main__":
    
    ct, iv = encrypt_random_string()
    assert padding_oracle(ct, iv)
    
    ivs = iv + ct
    
    recovered = bytes()
    for i in range(len(ct)//16):
        block = ct[16*i:16*(i+1)]  # ith block of ct 
        recovered_block = bytes()
        for j in range(1, 17):
            for c in range(256):
                prev_block = bytes([255]*(16-j)) + fixed_xor(bytes([c])+ recovered_block, bytes([j]*j))
                if padding_oracle(prev_block + block, iv):
                    recovered_block = bytes([c]) + recovered_block
                    break
                elif c == 255:
                    raise ValueError('Invalid character')
        block_iv = ivs[16*i:16*(i+1)]
        recovered += fixed_xor(recovered_block, block_iv)
    recovered = pkcs7.unpad(recovered)
    
    assert recovered == pkcs7.unpad(aes_cbc.decrypt(ct, KEY, iv))

