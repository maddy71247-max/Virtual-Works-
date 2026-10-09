"""Heuristic phishing-risk analyzer for raw email text and headers."""
from __future__ import annotations

import argparse
import email
import json
import re
from dataclasses import asdict, dataclass
from email.message import Message
from urllib.parse import urlparse


@dataclass(frozen=True)
class RiskReport:
    score: int
    classification: str
    indicators: list[str]


URGENCY_PATTERNS = ("immediate action required", "account suspended", "act now", "urgent", "verify your account", "final warning")
SENSITIVE_PATTERNS = ("password", "social security", "ssn", "one-time password", "otp", "security code", "credit card", "bank account")
URL_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)


def _body_text(message: Message, raw: str) -> str:
    if message.is_multipart():
        parts = [part.get_payload(decode=True) or b"" for part in message.walk() if part.get_content_type() == "text/plain"]
        return "\n".join(part.decode(part.get_content_charset() or "utf-8", errors="replace") for part in parts)
    payload = message.get_payload(decode=True)
    return payload.decode(message.get_content_charset() or "utf-8", errors="replace") if isinstance(payload, bytes) else str(payload or raw)


def _domain(value: str) -> str:
    match = EMAIL_RE.search(value or "")
    return match.group(0).rsplit("@", 1)[-1].lower() if match else ""


def analyze_email(raw_text: str) -> RiskReport:
    """Return a deterministic heuristic score from 0 to 100."""
    message = email.message_from_string(raw_text)
    searchable = f"{message.get('Subject', '')}\n{_body_text(message, raw_text)}".lower()
    indicators: list[str] = []
    score = 0

    urgency = [p for p in URGENCY_PATTERNS if p in searchable]
    if urgency:
        indicators.append("Urgency or threat language: " + ", ".join(urgency))
        score += min(25, 10 + 5 * (len(urgency) - 1))
    sensitive = [p for p in SENSITIVE_PATTERNS if p in searchable]
    if sensitive:
        indicators.append("Request or reference to sensitive credentials/data: " + ", ".join(sensitive))
        score += min(30, 15 + 5 * (len(sensitive) - 1))

    from_domain, reply_domain = _domain(message.get("From", "")), _domain(message.get("Reply-To", ""))
    if from_domain and reply_domain and from_domain != reply_domain:
        indicators.append(f"Sender mismatch: From domain {from_domain} differs from Reply-To domain {reply_domain}")
        score += 25
    if message.get("From") and not from_domain:
        indicators.append("Malformed or missing sender domain")
        score += 15

    urls = URL_RE.findall(raw_text)
    suspicious_urls: list[str] = []
    for url in urls:
        parsed = urlparse(url.rstrip(".,);"))
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) or "xn--" in host or "@" in parsed.netloc:
            suspicious_urls.append(url)
    if suspicious_urls:
        indicators.append("Suspicious link(s): " + ", ".join(suspicious_urls[:3]))
        score += min(25, 10 + 5 * (len(suspicious_urls) - 1))

    score = min(100, score)
    classification = "Safe" if score < 30 else "Suspicious" if score < 60 else "High Risk"
    return RiskReport(score, classification, indicators)


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze an email for phishing risk")
    parser.add_argument("file", help="raw .eml/text file, or - for stdin")
    args = parser.parse_args()
    import sys
    raw = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8", errors="replace").read()
    print(json.dumps(asdict(analyze_email(raw)), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
