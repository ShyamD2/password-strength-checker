"""
Optional online breach check against the Have I Been Pwned Pwned Passwords
API, using the k-Anonymity model: only the first 5 characters of the
password's SHA-1 hash are ever sent over the network, never the password
itself or the full hash.

Docs: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

import hashlib
from dataclasses import dataclass
from typing import Optional

try:
    import urllib.request
    import urllib.error
    _HAS_URLLIB = True
except ImportError:  # pragma: no cover
    _HAS_URLLIB = False

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
TIMEOUT_SECONDS = 5


@dataclass
class BreachResult:
    checked: bool
    breached: bool
    times_seen: int
    error: Optional[str] = None


def check_breach(password: str) -> BreachResult:
    if not password:
        return BreachResult(checked=False, breached=False, times_seen=0, error="Empty password")

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    if not _HAS_URLLIB:
        return BreachResult(checked=False, breached=False, times_seen=0, error="urllib unavailable")

    try:
        req = urllib.request.Request(
            API_URL.format(prefix=prefix),
            headers={"User-Agent": "advanced-password-strength-checker"},
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            body = resp.read().decode("utf-8")
    except Exception as exc:  # network unavailable, DNS blocked, etc.
        return BreachResult(checked=False, breached=False, times_seen=0, error=str(exc))

    for line in body.splitlines():
        hash_suffix, count = line.strip().split(":")
        if hash_suffix == suffix:
            return BreachResult(checked=True, breached=True, times_seen=int(count))

    return BreachResult(checked=True, breached=False, times_seen=0)
