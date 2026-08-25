"""
Cryptographic primitives using the Python 'cryptography' library.

- AES-256-GCM   : Symmetric encryption (file data)
- RSA-3072-OAEP : Asymmetric encryption (AES key protection)
- SHA-256       : Integrity hashing
"""

import os
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# ──────────────────────────────────────────────
#  AES-256-GCM
# ──────────────────────────────────────────────

def generate_aes_key() -> bytes:
    """Generate a random 256-bit (32-byte) AES key."""
    return AESGCM.generate_key(bit_length=256)


def generate_nonce() -> bytes:
    """Generate a random 96-bit (12-byte) nonce for AES-GCM."""
    return os.urandom(12)


def aes_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Encrypt data using AES-256-GCM.

    AES-GCM provides:
      - Confidentiality (encryption)
      - Authentication  (built-in auth tag)
      - Integrity       (any modification is detected)

    Args:
        plaintext: The raw file bytes to encrypt.
        key:       32-byte AES key.
        nonce:     12-byte unique nonce.

    Returns:
        Ciphertext with the 16-byte GCM auth tag appended.
    """
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, None)


def aes_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Decrypt data using AES-256-GCM.

    Automatically verifies the authentication tag.
    Raises cryptography.exceptions.InvalidTag if data was tampered with.

    Args:
        ciphertext: Encrypted bytes (includes GCM auth tag).
        key:        32-byte AES key.
        nonce:      12-byte nonce used during encryption.

    Returns:
        Original plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: Authentication failed.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ──────────────────────────────────────────────
#  RSA-3072
# ──────────────────────────────────────────────

def generate_rsa_key_pair():
    """
    Generate an RSA-3072 key pair.

    Returns:
        (private_key, public_key) objects.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key(private_key) -> bytes:
    """Serialize RSA private key to PEM format (no password)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_public_key(public_key) -> bytes:
    """Serialize RSA public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key_from_pem(pem_data: bytes):
    """Load an RSA private key from PEM bytes."""
    return serialization.load_pem_private_key(pem_data, password=None)


def load_public_key_from_pem(pem_data: bytes):
    """Load an RSA public key from PEM bytes."""
    return serialization.load_pem_public_key(pem_data)


def rsa_encrypt_key(aes_key: bytes, public_key) -> bytes:
    """
    Encrypt the AES key using RSA-3072-OAEP.

    OAEP padding with SHA-256 and MGF1(SHA-256).

    Args:
        aes_key:    The 32-byte AES key to protect.
        public_key: RSA public key object.

    Returns:
        RSA-encrypted AES key bytes.
    """
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt_key(encrypted_key: bytes, private_key) -> bytes:
    """
    Decrypt the AES key using RSA-3072-OAEP.

    Args:
        encrypted_key: RSA-encrypted AES key bytes.
        private_key:   RSA private key object.

    Returns:
        Original 32-byte AES key.

    Raises:
        ValueError: RSA decryption failed.
    """
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ──────────────────────────────────────────────
#  SHA-256 Hashing
# ──────────────────────────────────────────────

def calculate_sha256(data: bytes) -> str:
    """
    Calculate the SHA-256 hash of data.

    Args:
        data: Raw bytes.

    Returns:
        Hex-encoded SHA-256 digest string.
    """
    return hashlib.sha256(data).hexdigest()