"""
Cryptographically secure password generator using the `secrets` module
(CSPRNG-backed, safe for security-sensitive use — unlike `random`).
"""

import secrets
import string


def generate_password(length: int = 20, use_special: bool = True) -> str:
    alphabet = string.ascii_letters + string.digits
    if use_special:
        alphabet += "!@#$%^&*()-_=+[]{}"

    if length < 4:
        length = 4

    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        # Guarantee at least one of each required character class.
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and (not use_special or any(not c.isalnum() for c in password))):
            return password
