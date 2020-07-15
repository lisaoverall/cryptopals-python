#!/usr/bin/env python3

# Cryptopals Set 1 - Challenge 1
# Convert hex to base64

import base64

def hex_to_base64(s):
    raw = bytes.fromhex(s)
    b64 = base64.b64encode(raw)
    return b64.decode('utf-8')

if __name__ == '__main__':
    s = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    b64 = hex_to_base64(s)
    assert b64 == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
