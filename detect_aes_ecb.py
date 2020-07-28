#!/usr/bin/env python3

# Cryptopals Set 1 - Challenge 8
# Detect AES ECB
# Remember that the problem with ECB is that it is stateless and deterministic;
# the same 16 byte plaintext block will always produce 
# the same 16 byte ciphertext. 

from aes_ecb import *

if __name__ == '__main__':
    f = open("challenge-data/8.txt")
    cts_hex = [x.strip() for x in f.readlines()]
    f.close()

    cts = [bytes.fromhex(cth) for cth in cts_hex]
    
    scores = []
    for ct in cts:
        chunks = [ct[i:i+16] for i in range(0, len(ct), 16)]
        # unique chunks as a percentage of the total number of chunks
        score = len(set(chunks)) / len(chunks)
        scores.append(score)

    # low score (uniqueness) more indicative of ECB mode
    sorted_scores = sorted(enumerate(scores), key=lambda x: x[1])
    best = sorted_scores[0]
    
    assert best[0] == 132
