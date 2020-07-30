#!/usr/bin/env python3

# Cryptopals Set 3 - Challenge 21
# Implement MT19937

import numpy as np

class MT19937:
    w = 32
    n = 624
    m = 397
    r = 31
    a = 0x9908B0DF
    u = 11
    d = 0xFFFFFFFF
    s = 7
    b = 0x9D2C5680
    t = 15
    c = 0xEFC60000
    l = 18
    f = 1812433253

    lower_mask = (1 << r) - 1
    upper_mask = ((2**w) - 1) & (~lower_mask)

    def __init__(self):
        self.seed(5489)


    def seed(self, s):
        assert s < 2**(self.w)
        self.MT = [s]
        for i in range(1, self.n):
            self.MT.append(((2**self.w) - 1) & (self.f * (self.MT[i-1] ^ (self.MT[i-1] >> (self.w-2))) + i))
        self.index = self.n


    def __twist(self):
        for i in range(self.n):
            x = (self.MT[i] & self.upper_mask) + (self.MT[(i+1) % self.n] & self.lower_mask)
            xA = x >> 1
            if x % 2 != 0:
                xA = xA ^ self.a
            self.MT[i] = self.MT[(i+self.m) % self.n] ^ xA
        self.index = 0

    def rand(self):
        if self.index >= self.n:
            if self.index > self.n:
                raise Exception("Generator was never seeded")

            self.__twist()


        self.y = self.MT[self.index]
        self.y = self.y ^ ((self.y >> self.u) & self.d)
        self.y = self.y ^ ((self.y << self.s) & self.b)
        self.y = self.y ^ ((self.y << self.t) & self.c)
        self.y = self.y ^ (self.y >> self.l)

        self.index += 1
        # the shifting gets the lowest 32 bits
        return self.y  # ((2**self.w)-1) & self.y

    
if __name__ == "__main__":
    rng = MT19937()
    rng.seed(37)

    ref_rng = np.random.seed(37)

    for i in range(1000):
        assert rng.rand() == np.random.randint(0, 2**32-1)
