#!/usr/bin/env python3

# Cryptopals Set 3 - Challenge 22
# Crack time-seeded MT19937 

import random
import time
from mt19937 import MT19937


def time_seeded_rand():
    r = MT19937()
    t = int(time.time()) - random.randint(40, 1000)
    r.seed(t)
    return r.rand()

if __name__ == "__main__":
    r = time_seeded_rand()
    
    rng = MT19937()
    s = int(time.time())
    rng.seed(s)

    while rng.rand() != r:
        s -= 1
        rng.seed(s)
