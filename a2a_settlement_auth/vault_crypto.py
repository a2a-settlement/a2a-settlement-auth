"""
Vault Cryptography -- Encryption primitives for the Secret Vault.

Provides symmetric encryption for credential storage at rest using
Fernet (AES-128-CBC + HMAC-SHA256). The encryption key is supplied
by the caller from environment variables or a KMS.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken


class VaultDecryptionError(Exception):
    """Raised when decryption fails (wrong key or corrupted data)."""

    pass


class VaultCipher:
    """Symmetric encryption for secret values using Fernet.

    Usage:
        key = VaultCipher.generate_key()
        cipher = VaultCipher(key)
        encrypted = cipher.encrypt("ghp_my_real_pat_value")
        decrypted = cipher.decrypt(encrypted)
    """

    def __init__(self, key: str | bytes):
        if isinstance(key, str):
            key = key.encode("utf-8")
        self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a plaintext string, returning a URL-safe base64 token."""
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a Fernet token back to the original plaintext.

        Raises:
            VaultDecryptionError: If the key is wrong or data is corrupted.
        """
        try:
            return self._fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
        except InvalidToken:
            raise VaultDecryptionError(
                "Failed to decrypt secret value — wrong key or corrupted data"
            )

    @staticmethod
    def generate_key() -> str:
        """Generate a new Fernet encryption key (URL-safe base64)."""
        return Fernet.generate_key().decode("utf-8")
