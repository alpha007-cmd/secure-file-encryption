"""
Tests for the cryptographic functions.
Run with: pytest tests/test_crypto.py -v
"""

import os
import sys
import json
import base64
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.exceptions import InvalidTag
from app.crypto import (
    generate_aes_key,
    generate_nonce,
    aes_encrypt,
    aes_decrypt,
    generate_rsa_key_pair,
    rsa_encrypt_key,
    rsa_decrypt_key,
    calculate_sha256,
    serialize_private_key,
    serialize_public_key,
    load_private_key_from_pem,
    load_public_key_from_pem,
)
from app.encryption import encrypt_file, decrypt_file, create_tampered_package


# ──────────────────────────────────────────────
#  AES-256-GCM Tests
# ──────────────────────────────────────────────

class TestAES:
    def test_key_length(self):
        """AES key must be 32 bytes (256 bits)."""
        key = generate_aes_key()
        assert len(key) == 32

    def test_nonce_length(self):
        """Nonce must be 12 bytes (96 bits)."""
        nonce = generate_nonce()
        assert len(nonce) == 12

    def test_encrypt_decrypt(self):
        """AES encryption followed by decryption returns original data."""
        key = generate_aes_key()
        nonce = generate_nonce()
        plaintext = b"Hello, World! This is a test file."

        ciphertext = aes_encrypt(plaintext, key, nonce)
        decrypted = aes_decrypt(ciphertext, key, nonce)

        assert decrypted == plaintext

    def test_ciphertext_differs_from_plaintext(self):
        """Ciphertext must not equal plaintext."""
        key = generate_aes_key()
        nonce = generate_nonce()
        plaintext = b"Secret data 12345"

        ciphertext = aes_encrypt(plaintext, key, nonce)
        assert ciphertext != plaintext

    def test_wrong_key_fails(self):
        """Decryption with wrong key must raise InvalidTag."""
        key1 = generate_aes_key()
        key2 = generate_aes_key()
        nonce = generate_nonce()
        plaintext = b"Test data"

        ciphertext = aes_encrypt(plaintext, key1, nonce)

        with pytest.raises(InvalidTag):
            aes_decrypt(ciphertext, key2, nonce)

    def test_wrong_nonce_fails(self):
        """Decryption with wrong nonce must raise InvalidTag."""
        key = generate_aes_key()
        nonce1 = generate_nonce()
        nonce2 = generate_nonce()
        plaintext = b"Test data"

        ciphertext = aes_encrypt(plaintext, key, nonce1)

        with pytest.raises(InvalidTag):
            aes_decrypt(ciphertext, key, nonce2)

    def test_tampered_ciphertext_fails(self):
        """Modified ciphertext must raise InvalidTag."""
        key = generate_aes_key()
        nonce = generate_nonce()
        plaintext = b"Important data that must not be modified"

        ciphertext = aes_encrypt(plaintext, key, nonce)

        # Flip one byte
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises(InvalidTag):
            aes_decrypt(tampered, key, nonce)

    def test_empty_data(self):
        """AES-GCM should handle empty plaintext."""
        key = generate_aes_key()
        nonce = generate_nonce()
        plaintext = b""

        ciphertext = aes_encrypt(plaintext, key, nonce)
        decrypted = aes_decrypt(ciphertext, key, nonce)

        assert decrypted == plaintext

    def test_large_data(self):
        """AES-GCM should handle larger data."""
        key = generate_aes_key()
        nonce = generate_nonce()
        plaintext = os.urandom(1024 * 100)  # 100 KB

        ciphertext = aes_encrypt(plaintext, key, nonce)
        decrypted = aes_decrypt(ciphertext, key, nonce)

        assert decrypted == plaintext


# ──────────────────────────────────────────────
#  RSA-3072 Tests
# ──────────────────────────────────────────────

class TestRSA:
    def test_key_generation(self):
        """RSA key pair should be generated."""
        private_key, public_key = generate_rsa_key_pair()
        assert private_key is not None
        assert public_key is not None

    def test_key_size(self):
        """RSA key should be 3072 bits."""
        private_key, public_key = generate_rsa_key_pair()
        assert private_key.key_size == 3072

    def test_key_serialization(self):
        """Keys should serialize to PEM and load back."""
        private_key, public_key = generate_rsa_key_pair()

        priv_pem = serialize_private_key(private_key)
        pub_pem = serialize_public_key(public_key)

        loaded_priv = load_private_key_from_pem(priv_pem)
        loaded_pub = load_public_key_from_pem(pub_pem)

        assert loaded_priv.key_size == 3072
        assert loaded_pub.key_size == 3072

    def test_encrypt_decrypt_aes_key(self):
        """RSA-OAEP should protect and recover AES key."""
        private_key, public_key = generate_rsa_key_pair()
        aes_key = generate_aes_key()

        encrypted = rsa_encrypt_key(aes_key, public_key)
        decrypted = rsa_decrypt_key(encrypted, private_key)

        assert decrypted == aes_key

    def test_wrong_private_key_fails(self):
        """Decryption with different private key must fail."""
        priv1, pub1 = generate_rsa_key_pair()
        priv2, pub2 = generate_rsa_key_pair()
        aes_key = generate_aes_key()

        encrypted = rsa_encrypt_key(aes_key, pub1)

        with pytest.raises(Exception):
            rsa_decrypt_key(encrypted, priv2)


# ──────────────────────────────────────────────
#  SHA-256 Tests
# ──────────────────────────────────────────────

class TestSHA256:
    def test_hash_consistency(self):
        """Same data must produce same hash."""
        data = b"Test data for hashing"
        h1 = calculate_sha256(data)
        h2 = calculate_sha256(data)
        assert h1 == h2

    def test_hash_length(self):
        """SHA-256 hex digest should be 64 characters."""
        h = calculate_sha256(b"test")
        assert len(h) == 64

    def test_different_data_different_hash(self):
        """Different data must produce different hashes."""
        h1 = calculate_sha256(b"data1")
        h2 = calculate_sha256(b"data2")
        assert h1 != h2


# ──────────────────────────────────────────────
#  Integration: Full Encrypt/Decrypt Workflow
# ──────────────────────────────────────────────

class TestIntegration:
    @pytest.fixture(autouse=True)
    def setup_keys(self, tmp_path):
        """Create temporary RSA keys for testing."""
        self.keys_dir = str(tmp_path / "keys")
        os.makedirs(self.keys_dir, exist_ok=True)

        private_key, public_key = generate_rsa_key_pair()
        with open(os.path.join(self.keys_dir, "private_key.pem"), "wb") as f:
            f.write(serialize_private_key(private_key))
        with open(os.path.join(self.keys_dir, "public_key.pem"), "wb") as f:
            f.write(serialize_public_key(public_key))

    def test_full_encrypt_decrypt(self):
        """Complete encrypt → decrypt workflow."""
        plaintext = b"This is my secret document content."
        filename = "test_document.txt"

        # Encrypt
        package_json, enc_meta = encrypt_file(plaintext, filename, self.keys_dir)
        assert enc_meta["original_filename"] == filename
        assert enc_meta["algorithm"] == "AES-256-GCM"

        # Decrypt
        package_bytes = package_json.encode("utf-8")
        decrypted, dec_meta = decrypt_file(package_bytes, self.keys_dir)

        assert decrypted == plaintext
        assert dec_meta["aes_auth"] == "VALID"
        assert dec_meta["sha256_match"] is True
        assert dec_meta["integrity"] == "VERIFIED"

    def test_sha256_matches(self):
        """SHA-256 of original and decrypted must match."""
        plaintext = b"Integrity test data"
        original_hash = calculate_sha256(plaintext)

        package_json, _ = encrypt_file(plaintext, "test.txt", self.keys_dir)
        decrypted, meta = decrypt_file(package_json.encode(), self.keys_dir)

        decrypted_hash = calculate_sha256(decrypted)
        assert original_hash == decrypted_hash
        assert meta["stored_sha256"] == meta["decrypted_sha256"]

    def test_tampered_package_fails(self):
        """Tampered ciphertext must cause decryption failure."""
        plaintext = b"Data that will be tampered with"

        package_json, _ = encrypt_file(plaintext, "test.txt", self.keys_dir)
        package_bytes = package_json.encode("utf-8")

        # Tamper
        tampered = create_tampered_package(package_bytes)

        with pytest.raises(ValueError) as exc_info:
            decrypt_file(tampered, self.keys_dir)

        assert "INTEGRITY" in str(exc_info.value) or "authentication" in str(exc_info.value).lower()

    def test_invalid_json_fails(self):
        """Non-JSON data must be rejected."""
        with pytest.raises(ValueError):
            decrypt_file(b"this is not json", self.keys_dir)

    def test_missing_fields_fails(self):
        """Package with missing fields must be rejected."""
        package = json.dumps({"version": 1}).encode()
        with pytest.raises(ValueError):
            decrypt_file(package, self.keys_dir)

    def test_binary_file(self):
        """System should handle binary files."""
        plaintext = os.urandom(5000)  # Random binary data

        package_json, _ = encrypt_file(plaintext, "binary.dat", self.keys_dir)
        decrypted, meta = decrypt_file(package_json.encode(), self.keys_dir)

        assert decrypted == plaintext
        assert meta["integrity"] == "VERIFIED"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])