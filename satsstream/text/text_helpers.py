from satsstream.core import decrypt

def decrypt_paragraph(ciphertext_hex: str, key_hex: str, iv_hex: str) -> str:
    """
    Decrypt a single paragraph of AES-256-CBC encrypted text.

    Args:
        ciphertext_hex (str): Hex-encoded encrypted paragraph.
        key_hex (str): Hex-encoded 32-byte AES key.
        iv_hex (str): Hex-encoded 16-byte IV.

    Returns:
        str: Decrypted plaintext paragraph.
    """
    return decrypt(ciphertext_hex, key_hex, iv_hex)
