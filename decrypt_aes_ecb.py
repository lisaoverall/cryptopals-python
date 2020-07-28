#!/usr/bin/env python3

# Cryptopals Set 2 - Challenge 12
# Decrypt AES ECB a byte at a time
# fixed, unknown string appended
# fixed, random key used

import base64
import random
import pkcs7
import aes_ecb

KEY = bytes([random.randint(0,255) for i in range(16)])

UNKNOWN_B64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" \
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" \
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" \
        "YnkK"
UNKNOWN = base64.b64decode(UNKNOWN_B64)


def encryption_oracle(pt):
    "Produce AES-128-ECB(your-string || unknown-string, random-key)."
    return aes_ecb.encrypt(pkcs7.pad_for_aes(pt + UNKNOWN), KEY)
    


if __name__ == "__main__":
    
    # discover block size
    len_empty_ct = len(encryption_oracle(b''))
    blocksize = None
    for i in range(1, 64):
        ct = encryption_oracle(b'a'*i)
        if len(ct) != len_empty_ct:  # grew by a block
            blocksize = len(ct) - len_empty_ct
            break
    assert blocksize == 16
    
    # detect that function is using ECB
    ct = encryption_oracle(b'A'*blocksize*2)
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    assert len(set(blocks)) != len(blocks)

    # brute force a byte at a time
    recovered = bytes()
    while len(recovered) < len_empty_ct:
        junk = b'A' * (len_empty_ct - len(recovered) - 1)
        junk_ct = encryption_oracle(junk)
        for i in range(256):
            guess = junk + recovered + bytes([i])
            if encryption_oracle(guess)[:len_empty_ct] == junk_ct[:len_empty_ct]:
                recovered += bytes([i])
                break
            # no more bytes to recover - padding
            elif i == 255: 
                npad = len_empty_ct - len(recovered) + 1
                recovered = recovered[:-1] + bytes([npad]*npad)
                break

    recovered = pkcs7.unpad(recovered)
    # print('decrypted string:', recovered)
