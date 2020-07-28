#!/usr/bin/env python3

# Cryptopals Set 2 - Challenge 14
# Take your oracle function from #12.
# Now generate a random count of random bytes and
# prepend this string to every plaintext.
# You are now doing:
# AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
# Same goal: decrypt the target-bytes

import base64
import random
import pkcs7
import aes_ecb
from aes_ecb_cbc_oracle import gen_random_bytes, gen_random_aes_key


KEY = gen_random_aes_key()
PREFIX = gen_random_bytes(random.randint(1, 32))

UNKNOWN_B64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" \
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" \
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" \
        "YnkK"
UNKNOWN = base64.b64decode(UNKNOWN_B64)

def _run(bs):
    return aes_ecb.encrypt(pkcs7.pad_for_aes(bs), KEY)
    
# def no_prefix_encryption_oracle(pt):
#     "Produce AES-128-ECB(attacker-controlled || target-bytes, random-key)"
#     return _run(pt + UNKNOWN)
    
def encryption_oracle(pt):
    "Produce AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)"
    return _run(PREFIX + pt + UNKNOWN)
    


if __name__ == "__main__":
    
    # discover block size
    len_empty_ct = len(encryption_oracle(b''))
    blocksize = None
    for i in range(1, 64):
        ct = encryption_oracle(b'a'*i)
        if len(ct) != len_empty_ct:  # grew a block
            blocksize = len(ct) - len_empty_ct
            break
    assert blocksize == 16
    
    # detect that function is using ECB
    # need * 3 because of the prefix
    ct = encryption_oracle(b'a'*blocksize*3)
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    assert len(set(blocks)) != len(blocks)

    # recover padding length
    npad = None
    for i in range(1, 16):
        if len(encryption_oracle(b'a'*i)) != len_empty_ct:
               npad = i
               break

    len_prefix_suffix = len_empty_ct - npad

    # recover prefix, suffix lengths
    len_prefix = None
    dist_prefix_to_block = None
    for i in range(16):
        ct = encryption_oracle(b'a'*i + b'b'*32)
        blocks = [ct[i*16:(i+1)*16] for i in range(len(ct)//16)]
        if len(blocks) != len(set(blocks)):
            # repeated ciphertext blocks
            # (len_prefix + i) % 16 == 0
            for k in range(len(blocks)-1):
                if blocks[k] == blocks[k+1]:
                    len_prefix = k * 16 - i
                    dist_prefix_to_block = i
                    break
                
    len_suffix = len_prefix_suffix - len_prefix
    
    # brute force suffix byte at a time
    recovered = bytes()
    suffix_width = ((len_suffix + 15) // 16) * 16
    while len(recovered) < len_suffix:
        junk = b'a' * (dist_prefix_to_block + suffix_width - len(recovered) - 1)
        junk_ct = encryption_oracle(junk)
        for i in range(256):
            guess = junk + recovered + bytes([i])
            if encryption_oracle(guess)[:len_prefix + dist_prefix_to_block + suffix_width] == junk_ct[:len_prefix + dist_prefix_to_block + suffix_width]:
                recovered += bytes([i])
                break
            # we don't need the "strip off padding" case
            # because we're constructing guesses in which
            # the padding would be a full block
            
    # print(f"recovered: {recovered}")
