"""Tests for password_strength.py."""

import unittest

from task1_password_checker.password_checker import evaluate_password


class PasswordStrengthTests(unittest.TestCase):
    def test_strong_password_meets_all_checks(self) -> None:
        result = evaluate_password("Correct-Horse9!X")

        self.assertEqual(result.classification, "Strong")
        self.assertEqual(result.score, result.max_score)
        self.assertEqual(result.suggestions, [])
        self.assertIn("Strong password", result.message)

    def test_short_password_is_weak_with_actionable_feedback(self) -> None:
        result = evaluate_password("abc")

        self.assertEqual(result.classification, "Weak")
        self.assertIn("Use at least 8 characters.", result.suggestions)
        self.assertIn("Add at least one uppercase letter (A-Z).", result.suggestions)
        self.assertIn("Add at least one numerical digit (0-9).", result.suggestions)
        self.assertIn("Add at least one special character", " ".join(result.suggestions))

    def test_partial_password_is_moderate(self) -> None:
        result = evaluate_password("abcdefgh1")

        self.assertEqual(result.classification, "Moderate")
        self.assertTrue(result.criteria["minimum_length"])
        self.assertFalse(result.criteria["uppercase"])
        self.assertFalse(result.criteria["special_character"])

    def test_result_can_be_serialized(self) -> None:
        result = evaluate_password("Abcdef12!")

        serialized = result.to_dict()
        self.assertEqual(serialized["classification"], result.classification)
        self.assertIsInstance(serialized["criteria"], dict)


if __name__ == "__main__":
    unittest.main()
