#!/usr/bin/env python3

# Cryptopals Set 3 - Challenge 23
# Clone an MT19937 RNG from its output

from mt19937 import MT19937

# Each time MT19937 is tapped, an element of its internal state is subjected to a tempering function that diffuses bits through the result.

# When we talk about untempering, we are inverting
# the following excerpt from the MT19937's rand method.

# self.y = self.MT[self.index]
# self.y = self.y ^ ((self.y >> self.u) & self.d)
# self.y = self.y ^ ((self.y << self.s) & self.b)
# self.y = self.y ^ ((self.y << self.t) & self.c)
# self.y = self.y ^ (self.y >> self.l)
# ...
# return self.y

# Derive the inversions bit by bit,


def untemper(x):
    """Takes an MT19937 output and transforms it back into the corresponding element of the MT19937 state array."""
    assert x < 2**32

    b = 0x9D2C5680
    c = 0xEFC60000
    
    # 1) Invert self.y = self.y ^ (self.y >> self.l)
    # y' = y ^ (y >> 18)
    
    # y'_31 = y_31
    # y'_30 = y_30
    # ...
    # y'_14 = y_14
    # y'_13 = y_13 ^ y_31
    # ...
    # y'_0 = y_0 ^ y_18
    
    # Now try to write in terms of y',
    # using a ^ b = c -> b = a ^ c:
    # y_31 = y'_31
    # y_30 = y'_30
    # ...
    # y_14 = y'_14
    # y_13 = y'_13 ^ y_31
    # ...
    # y_0 = y'_0 ^ y_18
    
    # Finish up by substitution, e.g.:
    # y_31 = y'_31, so y_13 = y'_13 ^ y'_31

    # finally, back into a clean expression:
    # y = y' ^ (y >> 18)
    x ^= x >> 18

    # 2) Invert self.y = self.y ^ ((self.y << self.t) & self.c)
    # y' = y ^ (y >> 15) & c

    # y'_31 = y_31 ^ (y_16 & c_31)
    # y'_30 = y_30 ^ (y_15 & c_30)
    # y'_29 = y_29 ^ (y_14 & c_29)
    # ...
    # y'_16 = y_16 ^ (y_1 & c_16)
    # y'_15 = y_15 ^ (y_0 & c_15)
    # y'_14 = y_14
    # ...
    # y'_0 = y_0

    # y_31 = y'_31 ^ (y_16 & c_31)
    # y_30 = y'_30 ^ (y_15 & c_30)
    # y_29 = y'_29 ^ (y_14 & c_29)
    # ...
    # y_16 = y'_16 ^ (y_1 & c_16)
    # y_15 = y'_15 ^ (y_0 & c_15)
    # y_14 = y'_14
    # ...
    # y_0 = y'_0

    # y_31 = y'_31 ^ ((y'_16 ^ (y'_1 & c_16)) & c_31)
    # y_30 = y'_30 ^ ((y'_15 ^ (y'_0 & c_15)) & c_30)
    # y_29 = y'_29 ^ (y'_14 & c_29)
    # ...
    # y_16 = y'_16 ^ (y'_1 & c_16)
    # y_15 = y'_15 ^ (y'_0 & c_15)
    # y_14 = y'_14
    # ...
    # y_0 = y'_0

    # y = y' ^ ((y' ^ ((y' << 15) & c)) << 15) & c
    x ^= ((x^((x<<15)&c))<<15) & c
    
    # 3) invert self.y = self.y ^ ((self.y << self.s) & self.b)
    # y' = y ^ (y << 7) & b
    
    # y'_31 = y_31 ^ y_24 & b_31
    # ...
    # y'_28 = y_28 ^ y_21 & b_28
    # y'_27 = y_27 ^ y_20 & b_27
    # ...
    # y'_21 = y_21 ^ y_14 & b_21
    # y'_20 = y_20 ^ y_13 & b_20
    # ...
    # y'_14 = y_14 ^ y_7 & b_14
    # y'_13 = y_13 ^ y_6 & b_13
    # ...
    # y'_7 = y_7 ^ y_0 & b_7
    # y'_6 = y_6
    # ...
    # y'_0 = y_0
    
    # y_31 = y'_31 ^ (y'_24 ^ (y'_17 ^ (y'_10 ^ y'_3 & b_10) & b_17) & b_24) & b_31
    # ...
    # y_28 = y'_28 ^ (y'_21 ^ (y'_14 ^ (y'_7 ^ y'_0 & b_7) & b_14) & b_21) & b_28
    # y_27 = y'_27 ^ (y'_20 ^ (y'_13 ^ y'_6 & b_13) & b_20) & b_27
    # ...
    # y_21 = y'_21 ^ (y'_14 ^ (y'_7 ^ y'_0 & b_7) & b_14) & b_21
    # y_20 = y'_20 ^ (y'_13 ^ y'_6 & b_13) & b_20
    # ...
    # y_14 = y'_14 ^ (y'_7 ^ y'_0 & b_7) & b_14
    # y_13 = y'_13 ^ y'_6 & b_13
    # ...
    # y_7 = y'_7 ^ y'_0 & b_7
    # y_6 = y'_6
    # ...
    # y_0 = y'_0
    
    # y = y' ^ (((y'^(((y'^(((y'^((y'<<7)&b))<<7)&b))<<7)&b))<<7)&b)
    x ^= ((x^(((x^(((x^((x<<7)&b))<<7)&b))<<7)&b))<<7)&b


    # 4) invert self.y = self.y ^ ((self.y >> self.u) & self.d) - since d is all 1's, can drop the term
    # y' = y ^ (y >> 11)

    # y'_31 = y_31
    # ...
    # y'_21 = y_21
    # y'_20 = y_20 (+) y_31
    # ...
    # y'_10 = y_10 (+) y_21
    # y'_9 = y_9 (+) y_20
    # ...
    # y'_0 = y_0 (+) y_11
    
    # y_31 = y'_31
    # ...
    # y_21 = y'_21
    # y_20 = y'_20 (+) y'_31
    # ...
    # y_10 = y'_10 (+) y'_21
    # y_9 = y'_9 (+) y'_20 (+) y'_31
    # ...
    # y_0 = y'_0 (+) y'_11 (+) y'_22
    
    # y = y' ^ ((y' ^(y' >> 11)) >> 11)
    x ^= (x^(x>>11))>>11
    
    # self.y = self.MT[self.index]
    return x


if __name__ == "__main__":
    rng = MT19937()
    rng.seed(37)
    for i in range(624):
        y = rng.rand()
        uy = untemper(y)
        assert rng.MT[i] == uy

    rng = MT19937()
    rng.seed(37)
    ys = [rng.rand() for i in range(624)]
    uys = [untemper(y) for y in ys]

    rng2 = MT19937()
    rng2.MT = uys
    rng2.index = 624

    for i in range(1000):
        assert rng.rand() == rng2.rand()
    
