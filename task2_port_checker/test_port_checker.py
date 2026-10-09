import socket
import unittest
from unittest.mock import patch

from task2_port_checker.port_checker import check_port, parse_ports


class PortCheckerTests(unittest.TestCase):
    def test_parse_ports_and_ranges(self):
        self.assertEqual(parse_ports("80,443,8000-8002"), [80, 443, 8000, 8001, 8002])

    @patch("task2_port_checker.port_checker.socket.create_connection")
    def test_open_port(self, connect):
        connect.return_value.__enter__.return_value = object()
        self.assertEqual(check_port("example.test", 443).status, "OPEN")
        connect.assert_called_once_with(("example.test", 443), timeout=2.0)

    @patch("task2_port_checker.port_checker.socket.create_connection", side_effect=ConnectionRefusedError())
    def test_refused_port_is_closed_or_filtered(self, _connect):
        self.assertEqual(check_port("localhost", 9).status, "CLOSED/FILTERED")

    @patch("task2_port_checker.port_checker.socket.create_connection", side_effect=socket.timeout())
    def test_timeout_is_closed_or_filtered(self, _connect):
        self.assertEqual(check_port("localhost", 9).status, "CLOSED/FILTERED")

    def test_invalid_port_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("0")


if __name__ == "__main__":
    unittest.main()
