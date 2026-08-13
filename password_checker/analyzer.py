"""
Core scoring engine.

Combines character-pool entropy with pattern-based penalties to produce a
0-100 strength score and a human-readable strength category.
"""

import math
from dataclasses import dataclass, field
from typing import List

from .patterns import analyze_patterns, PatternMatch

STRENGTH_LEVELS = [
    (0, 20, "Very Weak"),
    (20, 40, "Weak"),
    (40, 60, "Fair"),
    (60, 80, "Good"),
    (80, 95, "Strong"),
    (95, 101, "Very Strong"),
]


@dataclass
class AnalysisResult:
    password_length: int
    pool_size: int
    entropy_bits: float
    raw_score: float
    score: int
    strength_label: str
    pattern_matches: List[PatternMatch] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


def character_pool_size(password: str) -> int:
    """Estimates the size of the character set the password draws from."""
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 33  # common printable special characters
    if any(ord(c) > 127 for c in password):
        pool += 100  # rough allowance for unicode/extended characters
    return max(pool, 1)


def shannon_entropy_bits(password: str) -> float:
    """Shannon entropy of the observed character distribution, in bits."""
    if not password:
        return 0.0
    freq = {}
    for c in password:
        freq[c] = freq.get(c, 0) + 1
    length = len(password)
    entropy_per_char = -sum(
        (count / length) * math.log2(count / length) for count in freq.values()
    )
    return entropy_per_char * length


def pool_based_entropy_bits(password: str) -> float:
    """Theoretical max entropy: length * log2(pool size)."""
    if not password:
        return 0.0
    pool = character_pool_size(password)
    return len(password) * math.log2(pool)


def _score_to_label(score: int) -> str:
    for low, high, label in STRENGTH_LEVELS:
        if low <= score < high:
            return label
    return "Very Strong"


def _build_suggestions(password: str, matches: List[PatternMatch]) -> List[str]:
    suggestions = []
    if len(password) < 12:
        suggestions.append("Use at least 12 characters — length is the single biggest factor in strength.")
    if not any(c.isupper() for c in password):
        suggestions.append("Add uppercase letters.")
    if not any(c.islower() for c in password):
        suggestions.append("Add lowercase letters.")
    if not any(c.isdigit() for c in password):
        suggestions.append("Add numbers.")
    if not any(not c.isalnum() for c in password):
        suggestions.append("Add special characters (e.g. !, @, #, %).")

    kinds_seen = {m.kind for m in matches}
    if "common_password" in kinds_seen or "common_password_leet" in kinds_seen:
        suggestions.append("Avoid well-known passwords, even with number/symbol substitutions.")
    if "keyboard_walk" in kinds_seen:
        suggestions.append("Avoid keyboard patterns like 'qwerty' or 'asdfgh'.")
    if "sequential_chars" in kinds_seen:
        suggestions.append("Avoid sequential characters like 'abcd' or '1234'.")
    if "repeated_chars" in kinds_seen:
        suggestions.append("Avoid repeating the same character multiple times in a row.")
    if "date_pattern" in kinds_seen:
        suggestions.append("Avoid using birth years or dates — these are commonly guessed.")
    if "common_substring" in kinds_seen:
        suggestions.append("Avoid basing your password around a common word, even with extra characters added.")

    if not suggestions:
        suggestions.append("This password looks strong. Still, use a unique password per site and a password manager.")

    return suggestions


def analyze(password: str) -> AnalysisResult:
    if password is None:
        password = ""

    pool = character_pool_size(password)
    entropy = pool_based_entropy_bits(password)
    matches = analyze_patterns(password)

    # Base score maps entropy bits onto a 0-100 curve.
    # ~28 bits -> weak, ~60 bits -> good, ~100+ bits -> very strong.
    raw_score = min(100.0, (entropy / 100.0) * 100.0)

    # Empty / very short passwords are floored hard regardless of pool math.
    if len(password) == 0:
        raw_score = 0.0
    elif len(password) < 6:
        raw_score = min(raw_score, 15.0)

    penalty_total = sum(m.penalty for m in matches)
    final_score = max(0, min(100, round(raw_score - penalty_total)))

    label = _score_to_label(final_score)
    suggestions = _build_suggestions(password, matches)

    return AnalysisResult(
        password_length=len(password),
        pool_size=pool,
        entropy_bits=round(entropy, 2),
        raw_score=round(raw_score, 2),
        score=final_score,
        strength_label=label,
        pattern_matches=matches,
        suggestions=suggestions,
    )
