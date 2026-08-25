import json
import base64
from typing import Tuple

from cryptography.exceptions import InvalidTag

from app.crypto import (
    generate_aes_key, generate_nonce, aes_encrypt, aes_decrypt,
    rsa_encrypt_key, rsa_decrypt_key, calculate_sha256,
    generate_salt, derive_key_from_password  # NEW IMPORTS
)
from app.key_manager import load_public_key, load_private_key


def encrypt_file(file_data: bytes, filename: str, keys_dir: str, password: str) -> Tuple[str, dict]:
    # 1. AES Encrypt the file
    aes_key = generate_aes_key()
    nonce = generate_nonce()
    ciphertext = aes_encrypt(file_data, aes_key, nonce)
    sha256_hash = calculate_sha256(file_data)

    # 2. RSA Protect the AES key (Assignment requirement)
    public_key = load_public_key(keys_dir)
    rsa_encrypted_aes_key = rsa_encrypt_key(aes_key, public_key)

    # 3. PASSWORD LOCK: Encrypt the RSA block with the user's password
    salt = generate_salt()
    pwd_key = derive_key_from_password(password, salt)
    pwd_nonce = generate_nonce()
    # AES-GCM encrypts the RSA key using the password-derived key
    locked_aes_key = aes_encrypt(rsa_encrypted_aes_key, pwd_key, pwd_nonce)

    # 4. Build Package
    package = {
        "version": 2,
        "algorithm": "AES-256-GCM",
        "key_protection": "RSA-3072-OAEP + PBKDF2-Password",
        "original_filename": filename,
        "original_size": len(file_data),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "salt": base64.b64encode(salt).decode("utf-8"),
        "pwd_nonce": base64.b64encode(pwd_nonce).decode("utf-8"),
        "locked_aes_key": base64.b64encode(locked_aes_key).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "sha256": sha256_hash,
    }

    metadata = {
        "original_filename": filename,
        "original_size": len(file_data),
        "algorithm": "AES-256-GCM",
        "key_protection": "RSA-3072 + Password",
        "sha256": sha256_hash,
    }

    return json.dumps(package, indent=2), metadata


def decrypt_file(package_data: bytes, keys_dir: str, password: str) -> Tuple[bytes, dict]:
    try:
        package = json.loads(package_data.decode("utf-8"))
    except Exception:
        raise ValueError("Invalid encrypted package: not valid JSON.")

    try:
        nonce = base64.b64decode(package["nonce"])
        salt = base64.b64decode(package["salt"])
        pwd_nonce = base64.b64decode(package["pwd_nonce"])
        locked_aes_key = base64.b64decode(package["locked_aes_key"])
        ciphertext = base64.b64decode(package["ciphertext"])
        stored_sha256 = package["sha256"]
    except Exception:
        raise ValueError("Invalid encrypted package: Base64 decoding failed.")

    # 1. PASSWORD UNLOCK: Attempt to decrypt the RSA block
    pwd_key = derive_key_from_password(password, salt)
    try:
        rsa_encrypted_aes_key = aes_decrypt(locked_aes_key, pwd_key, pwd_nonce)
    except InvalidTag:
        raise ValueError("INCORRECT PASSWORD: The package is valid, but the password provided is incorrect.")

    # 2. RSA Decrypt the AES key
    try:
        private_key = load_private_key(keys_dir)
        aes_key = rsa_decrypt_key(rsa_encrypted_aes_key, private_key)
    except Exception:
        raise ValueError("RSA decryption failed. Server key mismatch.")

    # 3. AES Decrypt the file
    try:
        plaintext = aes_decrypt(ciphertext, aes_key, nonce)
    except InvalidTag:
        raise ValueError("INTEGRITY CHECK FAILED\n\nAES-GCM authentication failed. File tampered.")

    # 4. SHA-256 Check
    decrypted_sha256 = calculate_sha256(plaintext)
    sha256_match = decrypted_sha256 == stored_sha256

    if not sha256_match:
        raise ValueError("SHA-256 MISMATCH. File corrupted.")

    metadata = {
        "original_filename": package.get("original_filename", "unknown"),
        "original_size": package.get("original_size", len(plaintext)),
        "algorithm": package["algorithm"],
        "key_protection": package["key_protection"],
        "aes_auth": "VALID",
        "integrity": "VERIFIED"
    }

    return plaintext, metadata

# IMPORTANT: Update create_tampered_package to handle the new version format
def create_tampered_package(package_data: bytes) -> bytes:
    package = json.loads(package_data.decode("utf-8"))
    ct_bytes = bytearray(base64.b64decode(package["ciphertext"]))
    if len(ct_bytes) > 0:
        ct_bytes[0] ^= 0xFF
    package["ciphertext"] = base64.b64encode(bytes(ct_bytes)).decode("utf-8")
    return json.dumps(package, indent=2).encode("utf-8")