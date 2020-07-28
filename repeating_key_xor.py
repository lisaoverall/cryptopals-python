#!/usr/bin/env python3

# Crytopals Set 1 - Challenge 5 
# Implement repeating key xor

def encrypt(pt, key):
    return bytes([p ^ key[i % len(key)] for (i, p) in enumerate(pt)])

def decrypt(ct, key):
    return bytes([c ^ key[i % len(key)] for (i, c) in enumerate(ct)])

if __name__ == '__main__':
    pt = "Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal"
    key = "ICE"
    
    pt_raw = pt.encode('utf-8')
    key_raw = key.encode('utf-8')

    ct_raw = encrypt(pt_raw, key_raw)
    assert ct_raw.hex() == '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

