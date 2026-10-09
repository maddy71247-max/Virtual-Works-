"""Password strength evaluation utilities and command-line interface.

The evaluator is intentionally heuristic: it checks common composition rules but
cannot detect breached, reused, or dictionary-based passwords.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from getpass import getpass
from typing import Any


MIN_LENGTH = 8
BONUS_LENGTH = 12


@dataclass(frozen=True)
class PasswordStrengthResult:
    """Structured result returned by :func:`evaluate_password`."""

    score: int
    max_score: int
    classification: str
    criteria: dict[str, bool]
    suggestions: list[str]
    message: str

    def to_dict(self) -> dict[str, Any]:
        """Return the result in a serialization-friendly dictionary format."""
        return asdict(self)


def evaluate_password(password: str) -> PasswordStrengthResult:
    """Evaluate ``password`` against length and character-composition rules.

    The base score has five points: minimum length, uppercase, lowercase,
    digit, and special character. Passwords with at least 12 characters receive
    one additional length bonus point, for a maximum score of six.
    """
    criteria = {
        "minimum_length": len(password) >= MIN_LENGTH,
        "twelve_or_more_characters": len(password) >= BONUS_LENGTH,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digit": bool(re.search(r"[0-9]", password)),
        # Match a non-whitespace character outside the ASCII letter/digit sets.
        "special_character": bool(re.search(r"[^A-Za-z0-9\s]", password)),
    }

    score = sum(criteria.values())
    suggestions: list[str] = []

    if not criteria["minimum_length"]:
        suggestions.append("Use at least 8 characters.")
    elif not criteria["twelve_or_more_characters"]:
        suggestions.append("Use 12 or more characters for extra strength.")
    if not criteria["uppercase"]:
        suggestions.append("Add at least one uppercase letter (A-Z).")
    if not criteria["lowercase"]:
        suggestions.append("Add at least one lowercase letter (a-z).")
    if not criteria["digit"]:
        suggestions.append("Add at least one numerical digit (0-9).")
    if not criteria["special_character"]:
        suggestions.append("Add at least one special character, such as !, @, or #.")

    # A complete password with 12+ characters is strong; partial matches are
    # still useful to describe as moderate rather than simply passing/failing.
    if score == len(criteria):
        classification = "Strong"
    elif score >= 3:
        classification = "Moderate"
    else:
        classification = "Weak"

    message = (
        "Strong password: it meets the recommended composition checks."
        if classification == "Strong" and not suggestions
        else "Improve this password using the suggestions below."
    )

    return PasswordStrengthResult(
        score=score,
        max_score=len(criteria),
        classification=classification,
        criteria=criteria,
        suggestions=suggestions,
        message=message,
    )


def _print_result(result: PasswordStrengthResult) -> None:
    """Render an evaluation result for terminal users."""
    print("\nPassword Strength Result")
    print("=" * 25)
    print(f"Score:          {result.score}/{result.max_score}")
    print(f"Classification: {result.classification}")
    print(f"\n{result.message}")

    if result.suggestions:
        print("\nSuggestions:")
        for suggestion in result.suggestions:
            print(f"- {suggestion}")


def main() -> None:
    """Read a password without echoing it and print the evaluation."""
    print("Password Strength Checker")
    print("Enter a password to evaluate (input is hidden).")
    password = getpass("Password: ")
    _print_result(evaluate_password(password))


if __name__ == "__main__":
    main()
