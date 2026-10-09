"""In-memory login attempt rate limiter and temporary lockout guard."""
from __future__ import annotations

import argparse
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class LoginStatus:
    allowed: bool
    locked: bool
    remaining_attempts: int
    unlock_in: int
    message: str


class LoginGuard:
    def __init__(self, threshold: int = 5, cooldown: float = 60.0, window: float | None = None, clock: Callable[[], float] = time.monotonic):
        if threshold < 1 or cooldown <= 0:
            raise ValueError("threshold must be positive and cooldown must be greater than zero")
        self.threshold, self.cooldown = threshold, cooldown
        self.window = window if window is not None else cooldown
        self._clock = clock
        self._failures: dict[str, deque[float]] = {}
        self._locked_until: dict[str, float] = {}

    def _prune(self, key: str, now: float) -> deque[float]:
        attempts = self._failures.setdefault(key, deque())
        while attempts and now - attempts[0] >= self.window:
            attempts.popleft()
        return attempts

    def status(self, key: str) -> LoginStatus:
        now = self._clock()
        attempts = self._prune(key, now)
        locked_until = self._locked_until.get(key, 0.0)
        if now < locked_until:
            seconds = max(1, int(locked_until - now + 0.999))
            return LoginStatus(False, True, 0, seconds, f"Account locked; try again in {seconds}s")
        self._locked_until.pop(key, None)
        remaining = max(0, self.threshold - len(attempts))
        return LoginStatus(True, False, remaining, 0, f"Allowed; {remaining} failed attempt(s) remaining")

    def record_failure(self, key: str) -> LoginStatus:
        current = self.status(key)
        if not current.allowed:
            return current
        now = self._clock()
        attempts = self._prune(key, now)
        attempts.append(now)
        if len(attempts) >= self.threshold:
            self._locked_until[key] = now + self.cooldown
            return self.status(key)
        return self.status(key)

    def record_success(self, key: str) -> LoginStatus:
        self._failures.pop(key, None)
        self._locked_until.pop(key, None)
        return LoginStatus(True, False, self.threshold, 0, "Login successful; attempt history cleared")


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect or update login lockout state")
    parser.add_argument("action", choices=("status", "failure", "success"))
    parser.add_argument("key", help="stable user ID or IP address")
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--cooldown", type=float, default=60.0)
    args = parser.parse_args()
    guard = LoginGuard(args.threshold, args.cooldown)
    action = {"status": guard.status, "failure": guard.record_failure, "success": guard.record_success}[args.action]
    print(action(args.key).message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
