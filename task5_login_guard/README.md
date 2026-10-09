# Task 5: Login Attempt Control System

`login_guard.py` tracks failed attempts by a user ID or IP key, applies a configurable threshold and cooldown, and returns clear status messages with remaining attempts and unlock countdowns. A successful login clears history.

## CLI

```bash
python -m task5_login_guard.login_guard failure user@example.com --threshold 3 --cooldown 30
python -m task5_login_guard.login_guard status user@example.com --threshold 3 --cooldown 30
python -m task5_login_guard.login_guard success user@example.com
```

The CLI creates a new in-memory guard for each invocation, so it demonstrates the API but does not persist state between commands. Applications should retain one `LoginGuard` instance or use a shared atomic store such as Redis for distributed deployments.

## Tests

```bash
python -m unittest -v task5_login_guard.test_login_guard
```
