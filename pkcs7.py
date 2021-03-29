#!/usr/bin/env python3

# Cryptopals Set 2 - Challenge 9
# implement PKCS#7 padding
# pad any block to a specific block length,
# by appending the number of bytes of padding to the end of the block.

# Cryptopals Set 2 - Challenge 15
# PKCS#7 padding validation

def pad(s, n):
    assert n < 256  # highest value of a padding byte is 0xff
    diff = n - len(s)
    return s + bytes([diff]*diff)  # empty list as arg to bytes returns b''

def unpad(s):
    padding_len = s[-1]
    padding = s[-padding_len:]
    if not all(p == padding_len for p in padding):
        raise ValueError("Invalid padding")
    return s[:-padding_len]

def is_padded(s):
    try:
        unpad(s)
    except ValueError:
        return False
    return True

def validate_padding(s):
    if is_padded(s):
        return unpad(s)
    else:
        raise ValueError("Invalid padding")

def pad_for_aes(pt):
    # (num_complete_blocks + partial_block(0/1)) * block_size
    ct_len = ((len(pt) // 16) + (len(pt) % 16 != 0)) * 16
    if len(pt) == ct_len:
        pt += pad(b'', 16)
    else:
        pt = pt[:-(len(pt) % 16)] + pad(pt[-(len(pt) % 16):], 16)
    assert len(pt) % 16 == 0
    return pt


if __name__ == '__main__':
    s = "YELLOW SUBMARINE"
    s_raw = s.encode('utf-8')
    assert pad(s_raw, 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04"
    assert unpad(b"YELLOW SUBMARINE\x04\x04\x04\x04") == s_raw

    assert pad_for_aes(s_raw) == s_raw + bytes([16]*16)
    assert pad_for_aes(s_raw[:-1]) == s_raw[:-1] + bytes([1])

    assert validate_padding(b"ICE ICE BABY\x04\x04\x04\x04") == b"ICE ICE BABY"
    assert not is_padded(b"ICE ICE BABY\x05\x05\x05\x05")
    assert not is_padded(b"ICE ICE BABY\x01\x02\x03\x04")
