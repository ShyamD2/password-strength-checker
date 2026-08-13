import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from password_checker.analyzer import analyze, character_pool_size
from password_checker.crack_time import estimate_crack_times, humanize_seconds
from password_checker.patterns import (
    find_repeated_chars,
    find_sequential_chars,
    find_keyboard_walks,
    leetspeak_normalize,
)
from password_checker.generator import generate_password
from password_checker.policy import check_policy, DEFAULT_POLICY


class TestCharacterPool(unittest.TestCase):
    def test_lowercase_only(self):
        self.assertEqual(character_pool_size("abcdef"), 26)

    def test_mixed_case_digits_special(self):
        pool = character_pool_size("Abc123!@#")
        self.assertEqual(pool, 26 + 26 + 10 + 33)

    def test_empty_password(self):
        self.assertEqual(character_pool_size(""), 1)


class TestPatternDetection(unittest.TestCase):
    def test_repeated_chars(self):
        matches = find_repeated_chars("aaabbbccc111")
        self.assertTrue(len(matches) >= 3)

    def test_sequential_ascending(self):
        matches = find_sequential_chars("abcdefg1234")
        kinds = [m.detail for m in matches]
        self.assertTrue(any("abcdefg" in d for d in kinds))

    def test_keyboard_walk(self):
        matches = find_keyboard_walks("qwerty")
        self.assertTrue(len(matches) >= 1)

    def test_leetspeak_normalize(self):
        self.assertEqual(leetspeak_normalize("P@ssw0rd"), "password")


class TestAnalyzer(unittest.TestCase):
    def test_common_password_scores_very_low(self):
        result = analyze("password")
        self.assertLess(result.score, 30)

    def test_strong_random_password_scores_high(self):
        result = analyze("xK9#mQ2$vL7&pR4!")
        self.assertGreater(result.score, 70)

    def test_empty_password_scores_zero(self):
        result = analyze("")
        self.assertEqual(result.score, 0)

    def test_short_password_capped(self):
        result = analyze("Ab1!")
        self.assertLessEqual(result.score, 20)


class TestCrackTime(unittest.TestCase):
    def test_humanize_seconds_instant(self):
        self.assertEqual(humanize_seconds(0.5), "instantly")

    def test_humanize_seconds_years(self):
        text = humanize_seconds(60 * 60 * 24 * 365 * 5)
        self.assertIn("year", text)

    def test_estimate_crack_times_returns_all_scenarios(self):
        estimates = estimate_crack_times(pool_size=95, length=12)
        self.assertEqual(len(estimates), 4)


class TestGenerator(unittest.TestCase):
    def test_generated_password_length(self):
        pw = generate_password(length=16)
        self.assertEqual(len(pw), 16)

    def test_generated_password_has_variety(self):
        pw = generate_password(length=20)
        self.assertTrue(any(c.islower() for c in pw))
        self.assertTrue(any(c.isupper() for c in pw))
        self.assertTrue(any(c.isdigit() for c in pw))

    def test_generated_password_strength(self):
        pw = generate_password(length=20)
        result = analyze(pw)
        self.assertGreaterEqual(result.score, 80)


class TestPolicy(unittest.TestCase):
    def test_policy_violation_short_password(self):
        policy = dict(DEFAULT_POLICY)
        policy["min_length"] = 12
        result = check_policy("short1!", policy, score=50, has_common_match=False)
        self.assertFalse(result.compliant)

    def test_policy_compliant(self):
        policy = dict(DEFAULT_POLICY)
        policy["min_length"] = 8
        policy["min_score"] = 30
        result = check_policy("xK9#mQ2$vL7&pR4!", policy, score=90, has_common_match=False)
        self.assertTrue(result.compliant)


if __name__ == "__main__":
    unittest.main()
