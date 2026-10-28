"""Password storage for Bayyina's local break-glass accounts. Rules: README.md, "What to build", part 3."""
from __future__ import annotations
"""Password hashing and verification for Bayyina Guard."""


import base64
import hashlib
import hmac
import unicodedata

# Current parameters.
_N = 2 ** 14
_R = 8
_P = 5
_DKLEN = 32
_SALT_LEN = 16
_MAXMEM = 64 * 1024 * 1024

# Bounds enforced on parsed parameters in verify_password / needs_rehash.
_N_MIN = 2
_N_MAX = 2 ** 20
_R_MIN = 1
_R_MAX = 32
_P_MIN = 1
_P_MAX = 16


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    # Reject non-ASCII early so we never feed garbage to the decoder.
    if not isinstance(text, str):
        raise ValueError("not a string")
    if any(ord(c) > 127 for c in text):
        raise ValueError("non-ascii base64")
    # Re-add padding to a multiple of 4.
    pad = (-len(text)) % 4
    return base64.urlsafe_b64decode(text + "=" * pad)


def _normalize(password: str) -> str:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    normalized = unicodedata.normalize("NFKC", password)
    if not (8 <= len(normalized) <= 128):
        raise ValueError("password must be 8 to 128 characters after NFKC")
    return normalized


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=_DKLEN,
        maxmem=_MAXMEM,
    )


def hash_password(password: str) -> str:
    normalized = _normalize(password)
    salt = __import__("os").urandom(_SALT_LEN)
    digest = _derive(normalized, salt, _N, _R, _P)
    return "$".join(
        [
            "scrypt",
            str(_N),
            str(_R),
            str(_P),
            _b64encode(salt),
            _b64encode(digest),
        ]
    )


def _parse(stored: str) -> tuple[int, int, int, bytes, bytes] | None:
    """Parse and range-check a stored string. Returns None if anything is wrong."""
    if not isinstance(stored, str):
        return None
    parts = stored.split("$")
    if len(parts) != 6:
        return None
    scheme, n_s, r_s, p_s, salt_s, hash_s = parts
    if scheme != "scrypt":
        return None

    # Integer parsing — strict: digits only, no sign, no whitespace.
    def _parse_int(s: str) -> int | None:
        if not s or not s.isascii() or not s.isdigit():
            return None
        # Reject leading zeros beyond the value 0 itself, to avoid ambiguity.
        if len(s) > 1 and s[0] == "0":
            return None
        try:
            return int(s)
        except ValueError:
            return None

    n = _parse_int(n_s)
    r = _parse_int(r_s)
    p = _parse_int(p_s)
    if n is None or r is None or p is None:
        return None

    # n must be a power of two in [2, 2**20].
    if n < _N_MIN or n > _N_MAX or (n & (n - 1)) != 0:
        return None
    # r in [1, 32], p in [1, 16].
    if not (_R_MIN <= r <= _R_MAX):
        return None
    if not (_P_MIN <= p <= _P_MAX):
        return None

    try:
        salt = _b64decode(salt_s)
        digest = _b64decode(hash_s)
    except Exception:
        return None

    if len(salt) < _SALT_LEN:
        return None
    if len(digest) != _DKLEN:
        return None

    return n, r, p, salt, digest


def verify_password(password: str, stored: str) -> bool:
    # Malformed stored value → False, never raise.
    parsed = _parse(stored)
    if parsed is None:
        return False
    n, r, p, salt, expected = parsed

    # Normalise the password like hash_password does. If the caller passes
    # something that would have failed hashing, verification simply fails.
    try:
        normalized = _normalize(password)
    except (TypeError, ValueError):
        return False

    # scrypt itself may still refuse the parameters (e.g. memory). Be defensive.
    try:
        candidate = _derive(normalized, salt, n, r, p)
    except (ValueError, MemoryError):
        return False

    return hmac.compare_digest(candidate, expected)


def needs_rehash(stored: str) -> bool:
    parsed = _parse(stored)
    if parsed is None:
        return True
    n, r, p, _salt, _digest = parsed
    return n < _N or r < _R or p < _P

def hash_password(password: str) -> str:
    """scrypt$<n>$<r>$<p>$<salt>$<hash> with n=2**14, r=8, p=5, a 16-byte random salt, dklen=32."""
    raise NotImplementedError


def verify_password(password: str, stored: str) -> bool:
    """True only if `password` matches `stored`. Never raises: anything malformed is False."""
    raise NotImplementedError


def needs_rehash(stored: str) -> bool:
    """True if `stored` cannot be parsed or any of n, r, p is below the current values."""
    raise NotImplementedError
