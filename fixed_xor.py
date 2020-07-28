#!/usr/bin/env python3

# Cryptopals Set 1 - Challenge 2
# Write a function that takes two equal-length buffers 
# and produces their XOR combination

def fixed_xor(a, b):
    assert len(a) == len(b)
    return bytes([x ^ y for x, y in zip(a,b)])


if __name__ == '__main__':
    a = '1c0111001f010100061a024b53535009181c'
    b = '686974207468652062756c6c277320657965'

    a_raw = bytes.fromhex(a)
    b_raw = bytes.fromhex(b)
    xor_ab = fixed_xor(a_raw, b_raw)
    hex_xor_ab = xor_ab.hex()

    assert hex_xor_ab == '746865206b696420646f6e277420706c6179'
