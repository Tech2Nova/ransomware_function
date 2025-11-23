# generate_keys.py (完整修复版)

import secrets

def generate_key(bit_length=128, return_bytes=True):
    byte_length = bit_length // 8
    if byte_length not in [16, 24, 32]:
        raise ValueError("bit_length must be 128, 192, or 256")
    key = secrets.token_bytes(byte_length)
    return key if return_bytes else key.hex()