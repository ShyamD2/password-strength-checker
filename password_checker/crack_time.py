"""
Crack time estimation across realistic attack scenarios.

Guess counts are estimated from the password's character pool size and
length (worst-case keyspace), then divided by published/typical guess
rates for each attack scenario. This mirrors the standard approach used
by tools like zxcvbn and haveibeenpwned's own guidance, simplified.
"""

from dataclasses import dataclass
from typing import List

# Guesses per second, by attack scenario.
ATTACK_SCENARIOS = [
    ("Online, rate-limited (10 guesses/hour)", 10 / 3600),
    ("Online, no rate limit (100 guesses/sec)", 100),
    ("Offline, slow hash - bcrypt/argon2 (10k guesses/sec)", 1e4),
    ("Offline, fast hash - MD5/SHA1 on GPU (10B guesses/sec)", 1e10),
]


@dataclass
class CrackTimeEstimate:
    scenario: str
    seconds: float
    human_readable: str


def humanize_seconds(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    intervals = [
        ("century", "centuries", 60 * 60 * 24 * 365 * 100),
        ("year", "years", 60 * 60 * 24 * 365),
        ("day", "days", 60 * 60 * 24),
        ("hour", "hours", 60 * 60),
        ("minute", "minutes", 60),
        ("second", "seconds", 1),
    ]
    for singular, plural, unit_seconds in intervals:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            label = singular if value == 1 else plural
            if value > 1_000_000:
                return f"{value:,.0f} {label} (effectively uncrackable)"
            return f"{value:,.1f} {label}"
    return "instantly"


def estimate_crack_times(pool_size: int, length: int) -> List[CrackTimeEstimate]:
    if length == 0:
        keyspace = 0
    else:
        keyspace = pool_size ** length

    results = []
    for scenario, rate in ATTACK_SCENARIOS:
        if keyspace == 0 or rate <= 0:
            seconds = 0.0
        else:
            # Average-case: attacker finds it after searching half the keyspace.
            seconds = (keyspace / 2) / rate
        results.append(CrackTimeEstimate(
            scenario=scenario,
            seconds=seconds,
            human_readable=humanize_seconds(seconds),
        ))
    return results
