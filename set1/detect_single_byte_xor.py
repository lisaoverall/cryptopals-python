#!/usr/bin/env python3

from single_byte_xor import *

# Cryptopals Set 1 - Challenge 4
# Detect single-byte XOR
# Figure out which ct is encoded this way


if __name__ == '__main__':
    f = open('4.txt') 
    cts = [ct.strip() for ct in f.readlines()]
    cts_raw = [bytes.fromhex(ct) for ct in cts]
    cts_best_score = [bruteforce(ct)[0] for ct in cts_raw]
    sorted_cts = sorted(cts_best_score, key=lambda x: x[2], reverse=True)
    best = sorted_cts[0]
    assert chr(best[0]) == '5'
    assert best[1] == b'Now that the party is jumping\n'

