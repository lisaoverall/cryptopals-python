#!/usr/bin/env python3

# Cryptopals Set 3 - Challenge 18
# Implement AES in CTR mode

# CTR mode does not require padding; when you run out of plaintext, you just stop XOR'ing keystream and stop generating keystream.

# Decryption is identical to encryption. Generate the same keystream, XOR, and recover the plaintext.

# Decrypt the string at the top of this function, then use your CTR function to encrypt and decrypt other things.

import base64
from types import FunctionType
from fixed_xor import fixed_xor
import aes_ecb
import pkcs7

class CTR:
    def __init__(self, encryptor, nonce=bytes(8)):
        assert type(encryptor) == FunctionType
        self.__encryptor = encryptor

        assert type(nonce) == bytes
        assert len(nonce) == 8
        self.__nonce = nonce

        self.__ctr = 0
        self.__keystream = bytes()

    def __grow_keystream(self):
        # format=64 bit unsigned little endian nonce,
        # 64 bit little endian block count (byte count / 16)
        self.__keystream += self.__encryptor(self.__nonce + self.__ctr.to_bytes(8, "little"))[:16]
        self.__ctr += 1

    def crypt(self, bs):
        assert type(bs) == bytes
        while len(self.__keystream) < len(bs):
            self.__grow_keystream()

        k = self.__keystream[:len(bs)]

        self.__keystream = self.__keystream[len(bs):]

        return fixed_xor(k, bs)


def AESCTR(key):
    return CTR(lambda x: aes_ecb.encrypt(x, key))


if __name__ == '__main__':
    ct_b64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    ct = base64.b64decode(ct_b64)

    # decrypts to something approximating English in CTR mode, with:
    key = b"YELLOW SUBMARINE"
    # nonce = 0 (default case)

    ctr = AESCTR(key)
    pt = ctr.crypt(ct)
    # print(pt)

    # counters of transmitting and receiving ends need to be kept in step
    ctr2 = AESCTR(key)
    pt = pkcs7.pad_for_aes(b'foobar')
    ct = ctr2.crypt(pt)
    ctr3 = AESCTR(key)
    assert ctr3.crypt(ct) == pt
