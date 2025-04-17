from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import binascii

def encrypt(plaintext: str, key_hex: str, iv_hex: str) -> str:
    """
    Encrypt plaintext using AES-256-CBC with PKCS7 padding.

    Args:
        plaintext (str): The input text to encrypt.
        key_hex (str): Hex-encoded 32-byte AES key.
        iv_hex (str): Hex-encoded 16-byte IV.

    Returns:
        str: Hex-encoded ciphertext.
    """
    key = binascii.unhexlify(key_hex)
    iv = binascii.unhexlify(iv_hex)
    data = plaintext.encode("utf-8")

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return binascii.hexlify(ciphertext).decode()

def decrypt_bytes(ciphertext_hex: str, key_hex: str, iv_hex: str) -> bytes:
    """
    Decrypt AES-256-CBC encrypted data and return raw bytes.

    Args:
        ciphertext_hex (str): Hex-encoded encrypted data.
        key_hex (str): Hex-encoded 32-byte AES key.
        iv_hex (str): Hex-encoded 16-byte IV.

    Returns:
        bytes: Raw decrypted bytes (unpadded).
    """
    ciphertext = binascii.unhexlify(ciphertext_hex)
    key = binascii.unhexlify(key_hex)
    iv = binascii.unhexlify(iv_hex)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

    return decrypted