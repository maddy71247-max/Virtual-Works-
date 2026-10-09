# Password Strength Checker

A clean, modular Python command-line tool for evaluating password strength using common security best practices. It provides a score, a `Weak`, `Moderate`, or `Strong` classification, and real-time suggestions for improving passwords that do not meet the recommended checks.

## Features

- **Length scoring:** Requires at least 8 characters and awards an additional strength point for passwords with 12 or more characters.
- **Character validation:** Checks for uppercase letters, lowercase letters, numerical digits, and special characters.
- **Secure input:** Uses Python's `getpass` module so passwords are hidden while entered in the terminal.
- **Actionable feedback:** Identifies missing criteria and explains exactly what to add.
- **Reusable core logic:** Exposes `evaluate_password()` as a function that returns a structured `PasswordStrengthResult` dataclass.
- **Automated tests:** Includes unit tests for classifications, scoring, feedback, and serialization.

## Requirements

- Python 3.9 or newer
- No third-party dependencies; the project uses only the Python standard library.

## Run the interactive CLI

From the project root, run:

```bash
python password_strength.py
```

Enter a password when prompted. Input is hidden, and the tool prints the score, classification, confirmation or improvement message, and any applicable suggestions.

Example output for a strong password:

```text
Password Strength Result
=========================
Score:          6/6
Classification: Strong
Strong password: it meets the recommended composition checks.
```

## Use `evaluate_password()` as a reusable module

Import the function into another Python program:

```python
from password_strength import evaluate_password

result = evaluate_password("Example-Password9!")

print(result.classification)  # Strong
print(result.score)           # 6
print(result.to_dict())       # Serialization-friendly dictionary
```

The returned `PasswordStrengthResult` includes:

- `score` and `max_score`
- `classification`
- `criteria`, a dictionary showing each check's result
- `suggestions`, a list of actionable improvements
- `message`, a user-facing summary

## Run automated unit tests

From the project root, run:

```bash
python -m unittest -v test_password_strength.py
```

The test suite covers weak, moderate, and strong passwords, feedback for missing criteria, and conversion of results to dictionaries.

## Scoring and classification

The tool awards one point for each of these six checks:

1. At least 8 characters
2. At least 12 characters (extra length point)
3. At least one uppercase letter (`A-Z`)
4. At least one lowercase letter (`a-z`)
5. At least one digit (`0-9`)
6. At least one special character

Classification is based on the resulting score:

- **Weak:** 0–2 points
- **Moderate:** 3–5 points
- **Strong:** 6 points

## Security notes

- Terminal input is hidden with `getpass`; passwords are not printed by the CLI.
- This is a heuristic strength checker, not a password security service. It does not check whether a password appears in breach databases, is commonly used, or has been reused elsewhere.
- Do not use real passwords in screenshots, logs, source code, or test fixtures. The example passwords in this repository are illustrative only.
- For production authentication systems, use a vetted password policy, secure password hashing such as Argon2id or bcrypt, multi-factor authentication, and breached-password screening where appropriate.

## Project files

```text
password_strength.py       # Core evaluator and interactive CLI
test_password_strength.py  # Automated unit tests
README.md                  # Project documentation
```
