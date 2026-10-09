# Task 4: File Protection Utility

`file_protector.py` encrypts files with Fernet authenticated encryption and derives password keys with PBKDF2-HMAC-SHA256 and a random per-file salt. Invalid passwords and corrupted files fail safely; decryption refuses to overwrite existing plaintext.

## CLI

```bash
python -m task4_file_protector.file_protector encrypt report.pdf
python -m task4_file_protector.file_protector decrypt report.pdf.enc
```

The CLI password argument is convenient for demonstrations. Production applications should use a hidden prompt or managed secret store.

## Python API

```python
from task4_file_protector.file_protector import encrypt_file, decrypt_file
encrypted = encrypt_file("report.pdf", "demo-password")
restored = decrypt_file(encrypted, "demo-password")
```

## Tests

```bash
python -m unittest -v task4_file_protector.test_file_protector
```
