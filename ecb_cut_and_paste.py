#!/usr/bin/env python3

# Cryptopals Set 2 - Challenge 13
# Using only the user input to profile_for()
# (as an oracle to generate "valid" ciphertexts)
# and the ciphertexts themselves, make a role=admin profile.

from aes_ecb_cbc_oracle import gen_random_aes_key 
import aes_ecb
import pkcs7

RANDOM_KEY = gen_random_aes_key()

def parse(s):
    kvs = s.split('&')
    kvs_split = [i.split('=') for i in kvs]
    return {i[0]: i[1] for i in kvs_split}

def encode(d):
    return '&'.join([str(k) + '=' + str(v) for k, v in list(d.items())])

def profile_for(s):
    if '&' in s or '=' in s:
        raise ValueError("Cannot have metacharacters &, = in email")
    if '@' not in s:
        raise ValueError("Invalid email: must contain @")
    d = {
        "email": s,
        "uid": 10,
        "role": 'user'
    }
    return encode(d)

def encrypt_profile_for(s):
    p = bytes(profile_for(s), 'ascii')
    ppad = pkcs7.pad_for_aes(p)
    return aes_ecb.encrypt(ppad, RANDOM_KEY)

def decrypt_profile(ct):
    ppad = aes_ecb.decrypt(ct, RANDOM_KEY)
    p = pkcs7.unpad(ppad)
    return parse(p.decode('ascii'))

if __name__ == "__main__":
    s = "foo=bar&baz=qux&zap=zazzle"
    d = {
        "foo": 'bar',
        "baz": 'qux',
        "zap": 'zazzle'
    }
    assert parse(s) == d
    assert encode(d) == s

    t = "foo@bar.com"
    p = {
        "email": 'foo@bar.com',
        "uid": 10,
        "role": 'user'
    }
    assert profile_for(t) == encode(p)

    # want 'email=<email>&uid=10&role='
    # to end on a block size boundary
    # so role value is at beginning of final block
    blocksize = 16
    email_len = blocksize*2 - len('email=&uid=10&role=')
    e = "foobar@xy.com"
    assert len(e) == email_len
    enc_e = encrypt_profile_for(e)

    # first block "email=' + 10 bytes of junk
    b1 = '\x00'*10
    # second block: 'admin' role value + padding
    b2 = 'admin' + '\x0b'*11 
    # third block: contains '@' to pass check
    b3 = '@xy.org'
    admin_addr = b1 + b2 + b3
    admin_block = encrypt_profile_for(admin_addr)[16:32]

    new_profile_ct = enc_e[:32] + admin_block
    d = decrypt_profile(new_profile_ct)
    assert d['role'] == "admin"
    
    
    
    
