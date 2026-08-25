"""
High-level encryption and decryption workflows.

Encrypt:
    file bytes  →  AES-256-GCM encrypt  →  RSA-OAEP protect key  →  JSON package

Decrypt:
    JSON package  →  RSA-OAEP recover key  →  AES-256-GCM decrypt  →  file bytes
"""

import json
import base64
from typing import Tuple

from cryptography.exceptions import InvalidTag

from app.crypto import (
    generate_aes_key,
    generate_nonce,
    aes_encrypt,
    aes_decrypt,
    rsa_encrypt_key,
    rsa_decrypt_key,
    calculate_sha256,
)
from app.key_manager import load_public_key, load_private_key


def encrypt_file(file_data: bytes, filename: str, keys_dir: str) -> Tuple[str, dict]:
    """
    Encrypt a file using hybrid cryptography.

    Steps:
        1. Read file data.
        2. Generate random AES-256 key (32 bytes).
        3. Generate random 12-byte nonce.
        4. Encrypt file with AES-256-GCM.
        5. Calculate SHA-256 of original file.
        6. Encrypt AES key with RSA-3072-OAEP.
        7. Build JSON encrypted package.

    Args:
        file_data: Raw bytes of the uploaded file.
        filename:  Original filename.
        keys_dir:  Path to the keys directory.

    Returns:
        (package_json_string, metadata_dict)
    """

    # Step 2 – Generate AES-256 key
    aes_key = generate_aes_key()

    # Step 3 – Generate nonce
    nonce = generate_nonce()

    # Step 4 – AES-256-GCM encrypt
    ciphertext = aes_encrypt(file_data, aes_key, nonce)

    # Step 5 – SHA-256 of plaintext
    sha256_hash = calculate_sha256(file_data)

    # Step 6 – RSA-OAEP protect AES key
    public_key = load_public_key(keys_dir)
    encrypted_aes_key = rsa_encrypt_key(aes_key, public_key)

    # Step 7 – Build encrypted package
    package = {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "key_protection": "RSA-3072-OAEP",
        "original_filename": filename,
        "original_size": len(file_data),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "sha256": sha256_hash,
    }

    package_json = json.dumps(package, indent=2)

    metadata = {
        "original_filename": filename,
        "original_size": len(file_data),
        "algorithm": "AES-256-GCM",
        "key_protection": "RSA-3072-OAEP",
        "sha256": sha256_hash,
    }

    return package_json, metadata


def decrypt_file(package_data: bytes, keys_dir: str) -> Tuple[bytes, dict]:
    """
    Decrypt an encrypted package using hybrid cryptography.

    Steps:
        1. Parse JSON package.
        2. Decode Base64 fields.
        3. RSA-OAEP decrypt the AES key.
        4. AES-256-GCM decrypt + authenticate.
        5. Calculate SHA-256 of decrypted data.
        6. Compare SHA-256 with stored hash.
        7. Return plaintext only if all checks pass.

    Args:
        package_data: Raw bytes of the uploaded .enc JSON file.
        keys_dir:     Path to the keys directory.

    Returns:
        (decrypted_bytes, metadata_dict)

    Raises:
        ValueError: If package is invalid or integrity check fails.
        InvalidTag: If AES-GCM authentication fails (tampering detected).
    """

    # Step 1 – Parse JSON
    try:
        package = json.loads(package_data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError("Invalid encrypted package: not valid JSON.")

    # Validate required fields
    required = [
        "version", "algorithm", "key_protection",
        "original_filename", "nonce", "encrypted_aes_key",
        "ciphertext", "sha256",
    ]
    for field in required:
        if field not in package:
            raise ValueError(f"Invalid encrypted package: missing '{field}'.")

    if package["algorithm"] != "AES-256-GCM":
        raise ValueError(f"Unsupported algorithm: {package['algorithm']}")

    if package["key_protection"] != "RSA-3072-OAEP":
        raise ValueError(f"Unsupported key protection: {package['key_protection']}")

    # Step 2 – Decode Base64
    try:
        nonce = base64.b64decode(package["nonce"])
        encrypted_aes_key = base64.b64decode(package["encrypted_aes_key"])
        ciphertext = base64.b64decode(package["ciphertext"])
    except Exception:
        raise ValueError("Invalid encrypted package: Base64 decoding failed.")

    stored_sha256 = package["sha256"]

    # Step 3 – RSA-OAEP decrypt AES key
    try:
        private_key = load_private_key(keys_dir)
        aes_key = rsa_decrypt_key(encrypted_aes_key, private_key)
    except Exception:
        raise ValueError(
            "RSA decryption failed. The file may have been encrypted "
            "with a different RSA key pair."
        )

    # Step 4 – AES-256-GCM decrypt (authenticates automatically)
    try:
        plaintext = aes_decrypt(ciphertext, aes_key, nonce)
    except InvalidTag:
        raise ValueError(
            "INTEGRITY CHECK FAILED\n\n"
            "AES-GCM authentication failed.\n"
            "The encrypted file may have been modified or corrupted.\n"
            "Decryption has been aborted."
        )

    # Step 5 – Calculate SHA-256 of decrypted data
    decrypted_sha256 = calculate_sha256(plaintext)

    # Step 6 – Compare hashes
    sha256_match = decrypted_sha256 == stored_sha256

    metadata = {
        "original_filename": package.get("original_filename", "unknown"),
        "original_size": package.get("original_size", len(plaintext)),
        "algorithm": package["algorithm"],
        "key_protection": package["key_protection"],
        "stored_sha256": stored_sha256,
        "decrypted_sha256": decrypted_sha256,
        "sha256_match": sha256_match,
        "aes_auth": "VALID",
        "integrity": "VERIFIED" if sha256_match else "SHA-256 MISMATCH",
    }

    if not sha256_match:
        raise ValueError(
            "SHA-256 MISMATCH\n\n"
            f"Expected: {stored_sha256}\n"
            f"Got:      {decrypted_sha256}\n"
            "The file content does not match the original."
        )

    return plaintext, metadata


def create_tampered_package(package_data: bytes) -> bytes:
    """
    Create a tampered version of an encrypted package for demonstration.

    Modifies one byte of the ciphertext so AES-GCM authentication will fail.

    Args:
        package_data: Valid encrypted package JSON bytes.

    Returns:
        Tampered package JSON bytes.
    """
    package = json.loads(package_data.decode("utf-8"))

    # Decode ciphertext, flip one byte, re-encode
    ct_bytes = bytearray(base64.b64decode(package["ciphertext"]))
    if len(ct_bytes) > 0:
        ct_bytes[0] ^= 0xFF  # Flip all bits of the first byte
    package["ciphertext"] = base64.b64encode(bytes(ct_bytes)).decode("utf-8")

    return json.dumps(package, indent=2).encode("utf-8")