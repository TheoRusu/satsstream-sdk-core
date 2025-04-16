import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
import hashlib
from cryptography.hazmat.backends import default_backend

from satsstream.core import verify_payment, decrypt, unlock_content
from satsstream.utils.crypto import encrypt

# Constants for testing
sample_preimage = "0f" * 32
expected_payment_hash = hashlib.sha256(bytes.fromhex(sample_preimage)).hexdigest()

key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
iv_hex = "1a2b3c4d5e6f77889900aabbccddeeff"
plaintext = "Hello World"

# Encrypt dynamically for matching ciphertext
ciphertext_hex = encrypt(plaintext, key_hex, iv_hex)

def test_verify_payment_valid():
    assert verify_payment(expected_payment_hash, sample_preimage) is True

def test_verify_payment_invalid():
    bad_preimage = "deadbeef" * 8
    assert verify_payment(expected_payment_hash, bad_preimage) is False

def test_decrypt_valid():
    decrypted = decrypt(ciphertext_hex, key_hex, iv_hex)
    assert decrypted == plaintext

def test_unlock_content_success():
    result = unlock_content(expected_payment_hash, sample_preimage, ciphertext_hex, key_hex, iv_hex)
    assert result == plaintext

def test_unlock_content_failure():
    bad_preimage = "deadbeef" * 8
    with pytest.raises(ValueError):
        unlock_content(expected_payment_hash, bad_preimage, ciphertext_hex, key_hex, iv_hex)

def test_verify_payment_non_hex_preimage():
    bad_preimage = "zz" * 32  # Not valid hex
    with pytest.raises(ValueError):
        verify_payment(expected_payment_hash, bad_preimage)

def test_decrypt_with_wrong_key():
    wrong_key_hex = "ff" * 32
    corrupted = False
    try:
        result = decrypt(ciphertext_hex, wrong_key_hex, iv_hex)
        if result != plaintext:
            corrupted = True
    except Exception:
        corrupted = True
    assert corrupted, "Decryption with wrong key should fail or return corrupted output"

def test_decrypt_with_invalid_padding():
    # Ciphertext with correct AES structure but wrong padding byte
    from satsstream.utils.crypto import decrypt_bytes
    bad_ciphertext = encrypt(plaintext, key_hex, iv_hex)
    
    # Corrupt last byte (padding byte)
    corrupted_hex = bad_ciphertext[:-2] + "00"
    with pytest.raises(ValueError):
        decrypt_bytes(corrupted_hex, key_hex, iv_hex)

def test_decrypt_non_utf8_content():
    # Encrypt binary data that is not valid UTF-8
    raw_bytes = b"\xff\xff\xff\xff\xff\xff\xff\xff"
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    import binascii
    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(raw_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    bad_ciphertext = encryptor.update(padded) + encryptor.finalize()
    bad_ciphertext_hex = binascii.hexlify(bad_ciphertext).decode()

    with pytest.raises(UnicodeDecodeError):
        decrypt(bad_ciphertext_hex, key_hex, iv_hex)

def test_unlock_content_with_corrupted_ciphertext():
    corrupted_ciphertext = ciphertext_hex[:-4] + "0000"  # Damage the last bytes
    with pytest.raises(Exception):
        unlock_content(expected_payment_hash, sample_preimage, corrupted_ciphertext, key_hex, iv_hex)

def test_repeated_decryption_is_deterministic():
    first = decrypt(ciphertext_hex, key_hex, iv_hex)
    second = decrypt(ciphertext_hex, key_hex, iv_hex)
    assert first == second == plaintext

def test_unlock_with_unrelated_ciphertext():
    # Encrypt different content with same key/iv
    unrelated_ciphertext = encrypt("Unrelated Data", key_hex, iv_hex)
    result = unlock_content(expected_payment_hash, sample_preimage, unrelated_ciphertext, key_hex, iv_hex)
    assert result != plaintext

@pytest.mark.parametrize("bad_input", [None, "", "zzzz", "0f"])
def test_verify_payment_garbage_inputs(bad_input):
    try:
        result = verify_payment(expected_payment_hash, bad_input)
        assert result is False
    except Exception:
        assert True  # Still okay if bad hex raises

def test_encrypt_decrypt_empty_string():
    empty_plaintext = ""
    encrypted = encrypt(empty_plaintext, key_hex, iv_hex)
    decrypted = decrypt(encrypted, key_hex, iv_hex)
    assert decrypted == empty_plaintext
