# Task 3: Email Risk Analyzer

`email_risk_analyzer.py` parses raw email text and headers, then checks urgency/threat language, credential or sensitive-data requests, mismatched sender/reply-to domains, and suspicious URLs.

## CLI

```bash
python -m task3_email_analyzer.email_risk_analyzer message.eml
cat message.txt | python -m task3_email_analyzer.email_risk_analyzer -
```

It returns JSON with a score from 0–100, a `Safe`, `Suspicious`, or `High Risk` classification, and itemized explanations. This heuristic is not a replacement for a mail gateway or human review.

## Tests

```bash
python -m unittest -v task3_email_analyzer.test_email_risk_analyzer
```
