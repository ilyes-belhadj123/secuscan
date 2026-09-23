"""Chiffrement des jetons d'accès GitHub / GitLab au repos (AES-256-GCM).

La clé vient de la variable d'environnement SECUSCAN_TOKEN_KEY (32 octets encodés en base64),
jamais de la base : une copie de la base seule ne permet pas de réutiliser les jetons.
Générer une clé :  python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
"""
import base64
import binascii
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_BYTES = 12
_VERSION = "v1"


class TokenKeyMissing(RuntimeError):
    """Clé de chiffrement absente ou invalide : les connexions Git privées sont désactivées."""


def _key(encoded: str) -> bytes:
    try:
        key = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TokenKeyMissing("SECUSCAN_TOKEN_KEY doit être encodée en base64.") from exc
    if len(key) != 32:
        raise TokenKeyMissing("SECUSCAN_TOKEN_KEY doit faire 32 octets (AES-256).")
    return key


def encrypt(plaintext: str, encoded_key: str, associated_data: str) -> str:
    """`associated_data` lie le chiffré à son propriétaire (ex. org:utilisateur:fournisseur)."""
    if not encoded_key:
        raise TokenKeyMissing("SECUSCAN_TOKEN_KEY n'est pas configurée.")
    nonce = os.urandom(_NONCE_BYTES)
    sealed = AESGCM(_key(encoded_key)).encrypt(nonce, plaintext.encode(), associated_data.encode())
    return f"{_VERSION}:{base64.b64encode(nonce + sealed).decode()}"


def decrypt(token: str, encoded_key: str, associated_data: str) -> str:
    if not encoded_key:
        raise TokenKeyMissing("SECUSCAN_TOKEN_KEY n'est pas configurée.")
    version, _, payload = token.partition(":")
    if version != _VERSION:
        raise ValueError("Format de jeton chiffré inconnu")
    raw = base64.b64decode(payload)
    return AESGCM(_key(encoded_key)).decrypt(raw[:_NONCE_BYTES], raw[_NONCE_BYTES:], associated_data.encode()).decode()
