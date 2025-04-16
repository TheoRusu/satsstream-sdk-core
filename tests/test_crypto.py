import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
import binascii
from satsstream.utils.crypto import encrypt, decrypt_bytes

# AES test key/IV
key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
iv_hex = "1a2b3c4d5e6f77889900aabbccddeeff"

def test_decrypt_bytes_valid():
    plaintext = "Test Block"
    encrypted = encrypt(plaintext, key_hex, iv_hex)
    decrypted = decrypt_bytes(encrypted, key_hex, iv_hex)
    assert decrypted.decode("utf-8") == plaintext

def test_decrypt_bytes_with_invalid_padding():
    valid = encrypt("Hello", key_hex, iv_hex)
    corrupted = valid[:-2] + "00"  # Corrupt last padding byte
    with pytest.raises(ValueError):
        decrypt_bytes(corrupted, key_hex, iv_hex)

def test_decrypt_bytes_with_short_ciphertext():
    short_ciphertext = "deadbeef"  # Not a full AES block
    with pytest.raises(ValueError):
        decrypt_bytes(short_ciphertext, key_hex, iv_hex)

def test_decrypt_bytes_with_non_hex_ciphertext():
    not_hex = "zzzzzzzz"
    with pytest.raises(binascii.Error):
        decrypt_bytes(not_hex, key_hex, iv_hex)

def test_decrypt_bytes_with_wrong_key():
    plaintext = "Secure content"
    encrypted = encrypt(plaintext, key_hex, iv_hex)
    wrong_key = "ff" * 32
    corrupted = False
    try:
        result = decrypt_bytes(encrypted, wrong_key, iv_hex)
        result.decode("utf-8")  # Optional check to catch decode noise
    except Exception:
        corrupted = True
    assert corrupted, "Decrypting with wrong key should fail or return garbage"
