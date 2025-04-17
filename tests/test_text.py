import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from satsstream.utils.crypto import encrypt
from satsstream.text.text_helpers import decrypt_paragraph

key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
iv_hex = "1a2b3c4d5e6f77889900aabbccddeeff"

def test_decrypt_paragraph_valid():
    plaintext = "This is a test paragraph."
    encrypted = encrypt(plaintext, key_hex, iv_hex)
    decrypted = decrypt_paragraph(encrypted, key_hex, iv_hex)
    assert decrypted == plaintext

def test_decrypt_paragraph_unicode():
    plaintext = "Unicode test — π, λ, and 🤖"
    encrypted = encrypt(plaintext, key_hex, iv_hex)
    decrypted = decrypt_paragraph(encrypted, key_hex, iv_hex)
    assert decrypted == plaintext
