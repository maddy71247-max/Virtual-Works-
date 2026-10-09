# Virtual Works Cybersecurity Utilities

A clean, defensive Python utility suite covering five educational cybersecurity tasks. Each task is isolated in its own folder with a source module, unit tests, and focused documentation.

## Repository layout

```text
task1_password_checker/  # Password composition-strength checker
task2_port_checker/      # TCP port status checker
task3_email_analyzer/    # Phishing-risk analyzer
task4_file_protector/    # Authenticated file encryption/decryption
task5_login_guard/       # Login rate limiting and lockout
requirements.txt
```

## Setup

Python 3.9+ is recommended.

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
python -m pip install -r requirements.txt
```

## Tasks and CLI examples

### Task 1: Password Strength Checker

Scores length and character composition, then returns `Weak`, `Moderate`, or `Strong` with actionable suggestions. Input is hidden by the interactive CLI.

```bash
python -m task1_password_checker.password_checker
```

See [`task1_password_checker/README.md`](task1_password_checker/README.md).

### Task 2: Port Status Checker

Performs authorized TCP connectivity checks with a configurable timeout. Comma-separated ports and inclusive ranges are supported.

```bash
python -m task2_port_checker.port_checker example.com 22,80,443-445 --timeout 1.5
```

See [`task2_port_checker/README.md`](task2_port_checker/README.md).

### Task 3: Email Risk Analyzer

Analyzes raw email text and headers for urgency, sensitive-data requests, sender mismatches, and suspicious URLs. It prints a JSON report with score, classification, and itemized indicators.

```bash
python -m task3_email_analyzer.email_risk_analyzer message.eml
cat message.txt | python -m task3_email_analyzer.email_risk_analyzer -
```

See [`task3_email_analyzer/README.md`](task3_email_analyzer/README.md).

### Task 4: File Protection Utility

Uses a random salt, PBKDF2-HMAC-SHA256, and Fernet authenticated encryption. Invalid passwords and corrupted files are rejected.

```bash
python -m task4_file_protector.file_protector encrypt report.pdf
python -m task4_file_protector.file_protector decrypt report.pdf.enc
```

See [`task4_file_protector/README.md`](task4_file_protector/README.md).

### Task 5: Login Attempt Control System

Tracks failures per user/IP key and reports remaining attempts, lockout state, and a cooldown countdown.

```bash
python -m task5_login_guard.login_guard failure user@example.com --threshold 3 --cooldown 30
python -m task5_login_guard.login_guard status user@example.com --threshold 3 --cooldown 30
```

The CLI is a one-shot demonstration; applications should keep one `LoginGuard` instance (or use a shared store in a distributed deployment). See [`task5_login_guard/README.md`](task5_login_guard/README.md).

## Run all tests

```bash
python -m unittest discover -v
```

Run an individual task's tests with, for example:

```bash
python -m unittest -v task3_email_analyzer.test_email_risk_analyzer
```

These tools are for authorized defensive testing and education. They are heuristics and should be complemented by appropriate production security controls.
