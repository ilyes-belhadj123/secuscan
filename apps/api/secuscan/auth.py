"""SS-2 — authentification : mots de passe, jetons de session et d'invitation, limitation des tentatives.

- Mots de passe : scrypt (bibliothèque standard), sel aléatoire par utilisateur.
- Sessions et invitations : jeton aléatoire opaque remis au client ; seule son empreinte SHA-256
  est stockée (une fuite de la base ne permet pas de réutiliser les sessions).
"""
import base64
import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque

_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}
MIN_PASSWORD_LENGTH = 10
SESSION_TTL_SECONDS = 7 * 24 * 3600
INVITATION_TTL_SECONDS = 7 * 24 * 3600
PASSWORD_RESET_TTL_SECONDS = 3600


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_b64, digest_b64 = stored.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    digest = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt_b64), **_SCRYPT)
    return hmac.compare_digest(digest, base64.b64decode(digest_b64))


# Empreinte factice : même coût de calcul quand l'e-mail est inconnu (pas d'énumération par le temps)
_DUMMY_HASH = hash_password(secrets.token_hex(16))


def verify_or_dummy(password: str, stored: str | None) -> bool:
    return verify_password(password, stored or _DUMMY_HASH) and stored is not None


def password_problem(password: str) -> str | None:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Le mot de passe doit contenir au moins {MIN_PASSWORD_LENGTH} caractères."
    if password.lower() == password or password.upper() == password or not any(c.isdigit() for c in password):
        return "Le mot de passe doit mélanger majuscules, minuscules et chiffres."
    return None


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class LoginRateLimiter:
    """Au plus `max_attempts` échecs par clé (e-mail ou IP) sur une fenêtre glissante."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 900):
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._failures: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque:
        q = self._failures[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def blocked(self, *keys: str) -> bool:
        now = time.monotonic()
        with self._lock:
            return any(len(self._prune(k, now)) >= self.max_attempts for k in keys)

    def fail(self, *keys: str) -> None:
        now = time.monotonic()
        with self._lock:
            for k in keys:
                self._prune(k, now).append(now)

    def reset(self, *keys: str) -> None:
        with self._lock:
            for k in keys:
                self._failures.pop(k, None)
