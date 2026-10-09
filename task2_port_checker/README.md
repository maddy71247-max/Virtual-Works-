# Task 2: Port Status Checker

`port_checker.py` uses Python's standard `socket` module to attempt TCP connections. A timeout, refusal, or network error is reported as `CLOSED/FILTERED`, because a TCP probe cannot always distinguish a closed port from firewall filtering.

## CLI

```bash
python -m task2_port_checker.port_checker example.com 22,80,443-445 --timeout 2
```

Only scan hosts and ports you own or are authorized to test.

## Tests

```bash
python -m unittest -v task2_port_checker.test_port_checker
```
