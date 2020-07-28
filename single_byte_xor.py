#!/usr/bin/env python3

from fixed_xor import *
import string

# Cryptopals Set 1 - Challenge 3
# Single-byte XOR
# Find key to decrypt message.
# Devise a scoring method for English plaintext.

# the table on wikipedia "letter frequency" has no space
# let's just give it a big weight and see what happens
# let's also add in some things to cover punctuation
LETTER_FREQS = {
    "a": .08497,   
    "b": .01492,
    "c": .02202,  
    "d": .04253,  
    "e": .11162,     
    "f": .02228,
    "g": .02015,
    "h": .06094,  
    "i": .07546,  
    "j": .00153,
    "k": .01292,
    "l": .04025,
    "m": .02406,
    "n": .06749,
    "o": .07507,  
    "p": .01929,  
    "q": .00095,
    "r": .07587,  
    "s": .06327,  
    "t": .09356,  
    "u": .02758,  
    "v": .00978,  
    "w": .02560,  
    "x": .00150,  
    "y": .01994,  
    "z": .00077,
    " ": 1,
    ".": .5,
    ",": .5,
    "?": .25,
    "!": .25,
    "-": .25,
    ":": .05,
    ";": .05
}

def score(pt):
    if all([c in set(string.printable.encode('utf-8')) for c in pt]):
        pt = [chr(c).lower() for c in pt]
        return sum([LETTER_FREQS.get(c, -1) for c in pt])
    return 0


def encrypt(pt, key):
    return fixed_xor(pt, bytes([key]*len(pt)))


def decrypt(ct, key):
    return fixed_xor(ct, bytes([key]*len(ct)))


def bruteforce(ct, n=1):
    putative_pts = [(i, decrypt(ct, i)) for i in range(256)]
    scores = sorted([(k, p, score(p)) for k, p in putative_pts], 
                    key=lambda x: x[2], reverse=True)
    return scores[:n]


if __name__ == '__main__':
    ct = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    ct_raw = bytes.fromhex(ct)
    scores = bruteforce(ct_raw)
    best = scores[0]
    assert chr(best[0]) == 'X'
    assert best[1] == b"Cooking MC's like a pound of bacon"
