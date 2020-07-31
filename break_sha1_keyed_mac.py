#!/usr/bin/env python3

# Cryptopals Set 4 - Challenge 29
# Break a SHA-1 keyed MAC using length extension

# The attack on secret-prefix SHA1 relies on the fact that you can take the ouput of SHA-1 and use it as a new starting point for SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it more data".

# Since the key precedes the data in secret-prefix, any additional data you feed the SHA-1 hash in this fashion will appear to have been hashed with the secret key.

# To carry out the attack, you'll need to account for the fact that SHA-1 is "padded" with the bit-length of the message; your forged message will need to include that padding. We call this "glue padding". The final message you actually forge will be:

# SHA1(key || original-message || glue-padding || new-message)
# (where the final padding on the whole constructed message is implied)

# Note that to generate the glue padding, you'll need to know the original bit length of the message; the message itself is known to the attacker, but the secret key isn't, so you'll need to guess at it.

import random
from sha1 import Sha1Hash
from sha1_keyed_mac import authenticate_msg
from aes_ecb_cbc_oracle import gen_random_bytes

# To implement the attack, first write the function that computes the MD padding of an arbitrary message and verify that you're generating the same padding that your SHA-1 implementation is using. This should take you 5-10 minutes.

def get_sha1_padding(msg):
    assert type(msg) == bytes
    return b'\x80' + b'\x00' * ((56 - (len(msg) + 1) % 64) % 64) + (len(msg)*8).to_bytes(8, 'big')



if __name__ == '__main__':

    k = gen_random_bytes(random.randint(16,32))
    msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    mac = authenticate_msg(k, msg)

    # Forge a variant of this message that ends with ";admin=true"

    # we don't know key length
    for i in range(16, 32):
        key_placeholder = bytes(i)
        padding = get_sha1_padding(key_placeholder + msg)
        new_msg = msg + padding + b';admin=true'

        # Now, take the SHA-1 secret-prefix MAC of the message you want to forge --- this is just a SHA-1 hash --- and break it into 32 bit SHA-1 registers (SHA-1 calls them "a", "b", "c", &c).
        
        h = tuple(int.from_bytes(mac[4*i:4*(i+1)], 'big') for i in range(5))
        sha1hash = Sha1Hash(h=h, message_byte_length=len(key_placeholder + msg + padding))
        sha1hash.update(b';admin=true')
        new_mac = sha1hash.digest()

        if new_mac == authenticate_msg(k, new_msg):
            break

    assert new_mac == authenticate_msg(k, new_msg)
