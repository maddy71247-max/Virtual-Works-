import tempfile
import unittest
from pathlib import Path

from task4_file_protector.file_protector import decrypt_file, encrypt_file


class FileProtectorTests(unittest.TestCase):
    def test_encrypt_and_decrypt_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "notes.txt"
            source.write_text("confidential message", encoding="utf-8")
            encrypted = encrypt_file(source, "correct horse battery staple")
            source.unlink()  # decryption refuses to overwrite existing plaintext
            restored = decrypt_file(encrypted, "correct horse battery staple")
            self.assertEqual(restored.read_text(encoding="utf-8"), "confidential message")
            self.assertNotEqual(encrypted.read_bytes(), restored.read_bytes())

    def test_wrong_password_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "data.bin"
            source.write_bytes(b"secret")
            encrypted = encrypt_file(source, "right")
            with self.assertRaises(ValueError):
                decrypt_file(encrypted, "wrong")

    def test_corrupted_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            encrypted = Path(directory) / "bad.enc"
            encrypted.write_bytes(b"not a protected file")
            with self.assertRaises(ValueError):
                decrypt_file(encrypted, "password")


if __name__ == "__main__":
    unittest.main()
