import hashlib
from satsstream.utils.crypto import decrypt_bytes

def verify_payment(payment_hash: str, preimage: str) -> bool:
    """
    Verify a Lightning payment by comparing the SHA-256 hash of the preimage
    to the expected payment hash.
    
    Args:
        payment_hash (str): Expected payment hash (from invoice), hex encoded.
        preimage (str): Payment preimage returned after payment, hex encoded.
    
    Returns:
        bool: True if the hash of the preimage matches the expected hash.
    """
    preimage_bytes = bytes.fromhex(preimage)
    computed_hash = hashlib.sha256(preimage_bytes).hexdigest()
    return computed_hash == payment_hash


def decrypt(ciphertext_hex: str, key_hex: str, iv_hex: str) -> str:
    """
    Decrypt AES-256-CBC encrypted text and return a UTF-8 string.
    
    Args:
        ciphertext_hex (str): Hex-encoded ciphertext.
        key_hex (str): Hex-encoded 32-byte AES key.
        iv_hex (str): Hex-encoded 16-byte IV.
    
    Returns:
        str: Decrypted plaintext string (UTF-8).
    """
    decrypted_bytes = decrypt_bytes(ciphertext_hex, key_hex, iv_hex)
    return decrypted_bytes.decode('utf-8')

def unlock_content(payment_hash: str, preimage: str, ciphertext_hex: str, key_hex: str, iv_hex: str) -> str:
    """
    Verifies payment and decrypts content in a single step.

    Args:
        payment_hash (str): Lightning invoice hash.
        preimage (str): Payment preimage.
        ciphertext_hex (str): Hex-encoded encrypted content.
        key_hex (str): Hex-encoded AES key.
        iv_hex (str): Hex-encoded IV.

    Returns:
        str: Decrypted content if payment is valid.

    Raises:
        ValueError: If payment is invalid.
    """
    if not verify_payment(payment_hash, preimage):
        raise ValueError("Invalid payment: preimage does not match hash.")

    return decrypt(ciphertext_hex, key_hex, iv_hex)

def log_unlock(platform_id: str, content_path: str, sats_paid: int, preimage: str):
    """
    Stub to log unlock event with the backend service.

    Args:
        platform_id (str): Unique identifier for the content creator/platform.
        content_path (str): Path or ID to the content within the platform (e.g., slug, URL).
        sats_paid (int): Amount paid in sats.
        preimage (str): Payment preimage (for hash verification).
    """
    pass  # Will be implemented later
