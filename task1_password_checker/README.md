# Task 1: Password Strength Checker

`password_checker.py` evaluates password composition without printing the password. It checks minimum length, 12-character bonus length, uppercase, lowercase, digit, and special character criteria.

## CLI

```bash
python -m task1_password_checker.password_checker
```

## Python API

```python
from task1_password_checker.password_checker import evaluate_password
result = evaluate_password("Example-Password9!")
print(result.classification, result.score)
```

Classifications are `Weak` (0–2), `Moderate` (3–5), and `Strong` (6). This is a composition heuristic; it does not check breach databases, reuse, or dictionary attacks.

## Tests

```bash
python -m unittest -v task1_password_checker.test_password_checker
```
