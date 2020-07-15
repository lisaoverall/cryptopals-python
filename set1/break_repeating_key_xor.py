#!/usr/bin/env python3

# Cryptopals Set 1 - Challenge 6
# Break repeating key xor

import base64
import itertools
import single_byte_xor
import repeating_key_xor

def hamming_dist(s1, s2):
    assert(len(s1) == len(s2))
    xor = int.from_bytes(s1, "big") ^ int.from_bytes(s2, "big")
    bitstr = "{0:b}".format(xor)
    return bitstr.count('1')


if __name__ == '__main__':
    assert hamming_dist(b'this is a test', b'wokka wokka!!!') == 37
    
    f = open('6.txt')
    ct_b64 = f.read()
    f.close()

    ct_raw = base64.b64decode(ct_b64)
    

    dists = [] 

    for KEYSIZE in range(2,41):
        chunks = [ct_raw[i:i+KEYSIZE] for i in range(0, len(ct_raw), KEYSIZE)]
        pairs = itertools.combinations(chunks[:4], 2)
        nhds = [hamming_dist(p[0], p[1]) / KEYSIZE for p in pairs]
        dists.append((KEYSIZE, sum(nhds) / len(nhds)))

    sorted_dists = sorted(dists, key=lambda x: x[1])
    k = sorted_dists[0][0]

    chunks = [ct_raw[i:i+k] for i in range(0, len(ct_raw), k)]
    transposes = []
    for i in range(k):
        t = bytearray()
        for c in chunks:
            if i < len(c):
                t.append(c[i])
        transposes.append(t)

    key = bytearray()
    for t in transposes:
        scores = single_byte_xor.bruteforce(t)
        best = scores[0]
        key.append(best[0])
    key = bytes(key)

    assert key == b'Terminator X: Bring the noise'

    pt_raw = repeating_key_xor.decrypt(ct_raw, key)
    # print(pt_raw)
