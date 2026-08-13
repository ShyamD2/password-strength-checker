"""
Password policy compliance checker.

Loads a JSON policy (or falls back to a sensible NIST 800-63B-inspired
default) and validates a password against it. Useful for CI pipelines,
signup form validation logic, or corporate password audits.
"""

import json
import re
from dataclasses import dataclass, field
from typing import List, Optional

DEFAULT_POLICY = {
    "min_length": 12,
    "max_length": 128,
    "require_uppercase": False,
    "require_lowercase": False,
    "require_digit": False,
    "require_special": False,
    "disallow_common_passwords": True,
    "min_score": 40,
}


@dataclass
class PolicyResult:
    compliant: bool
    violations: List[str] = field(default_factory=list)


def load_policy(path: Optional[str] = None) -> dict:
    if not path:
        return dict(DEFAULT_POLICY)
    with open(path, "r", encoding="utf-8") as f:
        user_policy = json.load(f)
    policy = dict(DEFAULT_POLICY)
    policy.update(user_policy)
    return policy


def check_policy(password: str, policy: dict, score: int, has_common_match: bool) -> PolicyResult:
    violations = []

    if len(password) < policy.get("min_length", 0):
        violations.append(f"Password must be at least {policy['min_length']} characters long.")
    if len(password) > policy.get("max_length", 999):
        violations.append(f"Password must be at most {policy['max_length']} characters long.")
    if policy.get("require_uppercase") and not any(c.isupper() for c in password):
        violations.append("Password must contain an uppercase letter.")
    if policy.get("require_lowercase") and not any(c.islower() for c in password):
        violations.append("Password must contain a lowercase letter.")
    if policy.get("require_digit") and not any(c.isdigit() for c in password):
        violations.append("Password must contain a digit.")
    if policy.get("require_special") and not any(not c.isalnum() for c in password):
        violations.append("Password must contain a special character.")
    if policy.get("disallow_common_passwords") and has_common_match:
        violations.append("Password matches a known common/breached password pattern.")
    if score < policy.get("min_score", 0):
        violations.append(f"Password strength score ({score}) is below the required minimum ({policy['min_score']}).")

    return PolicyResult(compliant=len(violations) == 0, violations=violations)
