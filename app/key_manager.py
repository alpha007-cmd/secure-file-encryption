"""
RSA Key Manager

Handles RSA-3072 key pair generation, storage, and loading.
Keys are stored in storage/keys/ as PEM files.
"""

import os
from app.crypto import (
    generate_rsa_key_pair,
    serialize_private_key,
    serialize_public_key,
    load_private_key_from_pem,
    load_public_key_from_pem,
)


def _private_key_path(keys_dir: str) -> str:
    return os.path.join(keys_dir, "private_key.pem")


def _public_key_path(keys_dir: str) -> str:
    return os.path.join(keys_dir, "public_key.pem")


def keys_exist(keys_dir: str) -> bool:
    """Check if both RSA key files exist."""
    return (
        os.path.isfile(_private_key_path(keys_dir))
        and os.path.isfile(_public_key_path(keys_dir))
    )


def generate_keys_if_missing(keys_dir: str) -> None:
    """
    Generate RSA-3072 key pair if they don't already exist.
    Called once on application startup.
    """
    if keys_exist(keys_dir):
        print("[KEY MANAGER] RSA-3072 keys found.")
        return

    print("[KEY MANAGER] Generating RSA-3072 key pair (this may take a moment)...")
    os.makedirs(keys_dir, exist_ok=True)

    private_key, public_key = generate_rsa_key_pair()

    with open(_private_key_path(keys_dir), "wb") as f:
        f.write(serialize_private_key(private_key))

    with open(_public_key_path(keys_dir), "wb") as f:
        f.write(serialize_public_key(public_key))

    print("[KEY MANAGER] RSA-3072 key pair generated and saved.")


def load_private_key(keys_dir: str):
    """Load the RSA private key from disk."""
    with open(_private_key_path(keys_dir), "rb") as f:
        return load_private_key_from_pem(f.read())


def load_public_key(keys_dir: str):
    """Load the RSA public key from disk."""
    with open(_public_key_path(keys_dir), "rb") as f:
        return load_public_key_from_pem(f.read())


def initialize_keys(keys_dir: str):
    """
    Full initialization: ensure keys exist and return them.

    Returns:
        (private_key, public_key) objects.
    """
    generate_keys_if_missing(keys_dir)
    return load_private_key(keys_dir), load_public_key(keys_dir)