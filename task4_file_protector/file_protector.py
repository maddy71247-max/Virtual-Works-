"""Authenticated file protection using PBKDF2-derived Fernet keys."""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

MAGIC = b"CSUITE-FERNET-1\0"
SALT_SIZE = 16
ITERATIONS = 390_000


def _key(password_or_key: str | bytes, salt: bytes) -> bytes:
    if isinstance(password_or_key, bytes) and len(password_or_key) == 32:
        return base64.urlsafe_b64encode(password_or_key)
    password = password_or_key.encode("utf-8") if isinstance(password_or_key, str) else password_or_key
    return base64.urlsafe_b64encode(hashlib.pbkdf2_hmac("sha256", password, salt, ITERATIONS, dklen=32))


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def encrypt_file(filepath: str | os.PathLike[str], password_or_key: str | bytes) -> Path:
    source = Path(filepath)
    if not source.is_file():
        raise FileNotFoundError(source)
    salt = os.urandom(SALT_SIZE)
    token = Fernet(_key(password_or_key, salt)).encrypt(source.read_bytes())
    destination = source.with_name(source.name + ".enc")
    _atomic_write(destination, MAGIC + salt + token)
    return destination


def decrypt_file(encrypted_filepath: str | os.PathLike[str], password_or_key: str | bytes) -> Path:
    source = Path(encrypted_filepath)
    data = source.read_bytes()
    if not data.startswith(MAGIC) or len(data) <= len(MAGIC) + SALT_SIZE:
        raise ValueError("invalid or corrupted protected file")
    salt_start = len(MAGIC)
    salt = data[salt_start : salt_start + SALT_SIZE]
    token = data[salt_start + SALT_SIZE :]
    try:
        plaintext = Fernet(_key(password_or_key, salt)).decrypt(token)
    except (InvalidToken, ValueError, TypeError) as exc:
        raise ValueError("invalid password/key or corrupted protected file") from exc
    destination = source.with_name(source.name[:-4] if source.name.endswith(".enc") else source.name + ".dec")
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite existing file: {destination}")
    _atomic_write(destination, plaintext)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file with a password")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("encrypt", "decrypt"):
        sub = subparsers.add_parser(command)
        sub.add_argument("file")
        sub.add_argument("password")
    args = parser.parse_args()
    result = encrypt_file(args.file, args.password) if args.command == "encrypt" else decrypt_file(args.file, args.password)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
