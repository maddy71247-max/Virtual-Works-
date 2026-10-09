import unittest

from task5_login_guard.login_guard import LoginGuard


class LoginGuardTests(unittest.TestCase):
    def test_lockout_and_countdown(self):
        now = [100.0]
        guard = LoginGuard(threshold=3, cooldown=30, clock=lambda: now[0])
        self.assertEqual(guard.status("alice").remaining_attempts, 3)
        guard.record_failure("alice")
        guard.record_failure("alice")
        locked = guard.record_failure("alice")
        self.assertTrue(locked.locked)
        self.assertFalse(locked.allowed)
        self.assertEqual(locked.unlock_in, 30)
        now[0] = 131.0
        self.assertTrue(guard.status("alice").allowed)

    def test_success_clears_history(self):
        guard = LoginGuard(threshold=3, cooldown=30)
        guard.record_failure("10.0.0.1")
        success = guard.record_success("10.0.0.1")
        self.assertTrue(success.allowed)
        self.assertEqual(success.remaining_attempts, 3)

    def test_invalid_configuration(self):
        with self.assertRaises(ValueError):
            LoginGuard(threshold=0)


if __name__ == "__main__":
    unittest.main()
