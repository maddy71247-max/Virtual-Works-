import unittest

from task3_email_analyzer.email_risk_analyzer import analyze_email


class EmailRiskAnalyzerTests(unittest.TestCase):
    def test_safe_email(self):
        report = analyze_email("From: team@example.com\nSubject: Hello\n\nThanks for the update.")
        self.assertEqual(report.classification, "Safe")
        self.assertEqual(report.score, 0)

    def test_phishing_indicators_are_itemized(self):
        raw = ("From: Billing <billing@trusted.example>\n"
               "Reply-To: thief@evil.example\n"
               "Subject: Immediate action required\n\n"
               "Your account is suspended. Verify your password and OTP at http://192.0.2.1/login")
        report = analyze_email(raw)
        self.assertEqual(report.classification, "High Risk")
        self.assertGreaterEqual(report.score, 60)
        self.assertGreaterEqual(len(report.indicators), 4)
        self.assertTrue(any("Sender mismatch" in item for item in report.indicators))
        self.assertTrue(any("Suspicious link" in item for item in report.indicators))

    def test_https_normal_link_does_not_trigger_link_indicator(self):
        report = analyze_email("From: news@example.com\n\nRead more at https://example.com/news")
        self.assertFalse(any("Suspicious link" in item for item in report.indicators))


if __name__ == "__main__":
    unittest.main()
