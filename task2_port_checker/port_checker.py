"""TCP port status checker.

This module intentionally performs only TCP connection attempts; it does not
send application data to the target service.
"""
from __future__ import annotations

import argparse
import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class PortResult:
    host: str
    port: int
    status: str
    detail: str = ""


def parse_ports(value: str) -> list[int]:
    """Parse comma-separated ports and inclusive ranges."""
    ports: set[int] = set()
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            start_text, end_text = item.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError("port range must start at or below its end")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(item))
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def check_port(host: str, port: int, timeout: float = 2.0) -> PortResult:
    """Attempt a TCP connection and classify the result.

    A timeout and common connection failures are reported as
    ``CLOSED/FILTERED`` because TCP alone cannot distinguish a closed port
    from a firewall silently dropping packets.
    """
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return PortResult(host, port, "OPEN", "TCP connection succeeded")
    except socket.gaierror as exc:
        return PortResult(host, port, "CLOSED/FILTERED", f"name resolution failed: {exc}")
    except (TimeoutError, socket.timeout) as exc:
        return PortResult(host, port, "CLOSED/FILTERED", f"connection timed out: {exc}")
    except (ConnectionRefusedError, ConnectionResetError, OSError) as exc:
        return PortResult(host, port, "CLOSED/FILTERED", str(exc))


def main() -> int:
    parser = argparse.ArgumentParser(description="Check TCP port status")
    parser.add_argument("host", help="IP address or domain name")
    parser.add_argument("ports", help="port, comma list, or inclusive range (for example 22,80,443-445)")
    parser.add_argument("--timeout", type=float, default=2.0, help="connection timeout in seconds (default: 2)")
    args = parser.parse_args()
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))
    for port in ports:
        result = check_port(args.host, port, args.timeout)
        print(f"{result.host}:{result.port} {result.status} - {result.detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
