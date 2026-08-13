"""
Pattern detection engine.

Detects structural weaknesses that make a password easier to guess than its
raw character-pool entropy suggests: keyboard walks, sequential runs,
repeated characters, dates, and dictionary/common-password matches
(including leetspeak-normalized matches).
"""

import re
import os
from dataclasses import dataclass
from typing import List

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
COMMON_PASSWORDS_PATH = os.path.join(DATA_DIR, "common_passwords.txt")

# Adjacency-based keyboard rows used to detect "walks" like qwerty, asdf, 98765
KEYBOARD_ROWS = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]

LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "!": "i", "3": "e", "4": "a",
    "@": "a", "5": "s", "$": "s", "7": "t", "+": "t", "8": "b",
})


@dataclass
class PatternMatch:
    kind: str
    detail: str
    penalty: int  # points subtracted from the strength score (0-100 scale)


def _load_common_passwords() -> set:
    try:
        with open(COMMON_PASSWORDS_PATH, "r", encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


COMMON_PASSWORDS = _load_common_passwords()


def leetspeak_normalize(password: str) -> str:
    return password.lower().translate(LEET_MAP)


def find_repeated_chars(password: str) -> List[PatternMatch]:
    """Detects 3+ repeats of the same character, e.g. 'aaa', '111'."""
    matches = []
    for m in re.finditer(r"(.)\1{2,}", password):
        matches.append(PatternMatch(
            kind="repeated_chars",
            detail=f"Repeated character run: '{m.group(0)}'",
            penalty=8,
        ))
    return matches


def find_sequential_chars(password: str, min_run: int = 3) -> List[PatternMatch]:
    """Detects ascending/descending runs like 'abcd', '4321', 'xyz'."""
    matches = []
    lower = password.lower()
    n = len(lower)
    i = 0
    while i < n - min_run + 1:
        asc = all(ord(lower[i + k + 1]) - ord(lower[i + k]) == 1 for k in range(min_run - 1))
        desc = all(ord(lower[i + k]) - ord(lower[i + k + 1]) == 1 for k in range(min_run - 1))
        if asc or desc:
            j = i + min_run
            while j < n:
                step = ord(lower[j]) - ord(lower[j - 1])
                if (asc and step == 1) or (desc and step == -1):
                    j += 1
                else:
                    break
            run = password[i:j]
            matches.append(PatternMatch(
                kind="sequential_chars",
                detail=f"Sequential run: '{run}'",
                penalty=10,
            ))
            i = j
        else:
            i += 1
    return matches


def find_keyboard_walks(password: str, min_run: int = 4) -> List[PatternMatch]:
    """Detects physically adjacent key sequences, e.g. 'qwerty', 'asdfgh'."""
    matches = []
    lower = password.lower()
    for row in KEYBOARD_ROWS:
        n = len(lower)
        i = 0
        while i < n - min_run + 1:
            window = lower[i:i + min_run]
            if window in row or window in row[::-1]:
                j = i + min_run
                while j < n:
                    ext_fwd = lower[i:j + 1]
                    if ext_fwd in row or ext_fwd in row[::-1]:
                        j += 1
                    else:
                        break
                matches.append(PatternMatch(
                    kind="keyboard_walk",
                    detail=f"Keyboard walk: '{password[i:j]}'",
                    penalty=12,
                ))
                i = j
            else:
                i += 1
    return matches


def find_date_patterns(password: str) -> List[PatternMatch]:
    """Detects years (1940-2029) and common date formats."""
    matches = []
    for m in re.finditer(r"(19[4-9]\d|20[0-2]\d)", password):
        matches.append(PatternMatch(
            kind="date_pattern",
            detail=f"Year-like number: '{m.group(0)}'",
            penalty=6,
        ))
    for m in re.finditer(r"\b(0?[1-9]|1[0-2])[./-](0?[1-9]|[12]\d|3[01])[./-]\d{2,4}\b", password):
        matches.append(PatternMatch(
            kind="date_pattern",
            detail=f"Date-like pattern: '{m.group(0)}'",
            penalty=8,
        ))
    return matches


def find_common_password_match(password: str) -> List[PatternMatch]:
    """Matches against a known common-password list, including leetspeak
    normalization (e.g. 'p@ssw0rd' -> 'password')."""
    matches = []
    lower = password.lower()
    normalized = leetspeak_normalize(password)

    if lower in COMMON_PASSWORDS:
        matches.append(PatternMatch(
            kind="common_password",
            detail=f"'{password}' appears in a common password list",
            penalty=40,
        ))
    elif normalized in COMMON_PASSWORDS:
        matches.append(PatternMatch(
            kind="common_password_leet",
            detail=f"'{password}' normalizes to a common password ('{normalized}')",
            penalty=30,
        ))
    else:
        # Substring containment check for longer passwords built around a
        # common word, e.g. "iloveyou2024!"
        for word in COMMON_PASSWORDS:
            if len(word) >= 5 and (word in lower or word in normalized):
                matches.append(PatternMatch(
                    kind="common_substring",
                    detail=f"Contains common password/word: '{word}'",
                    penalty=15,
                ))
                break
    return matches


def analyze_patterns(password: str) -> List[PatternMatch]:
    matches: List[PatternMatch] = []
    matches += find_common_password_match(password)
    matches += find_repeated_chars(password)
    matches += find_sequential_chars(password)
    matches += find_keyboard_walks(password)
    matches += find_date_patterns(password)
    return matches
