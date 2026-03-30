"""
Unit Tests for Assignment 2 — Port Scanner
"""

import unittest
from assignment2_101565577 import PortScanner, common_ports


class TestPortScanner(unittest.TestCase):
    def test_scanner_initialization(self):
        scanner=PortScanner("127.0.0.1")

        self.assertEqual(scanner.target, "127.0.0.1")

        self.assertEqual(scanner.scan_results,[])

    def test_get_open_ports_filters_correctly(self):
        scanner = PortScanner("127.0.0.1")
        scanner.scan_results.append((22, "Open", "SSH"))
        scanner.scan_results.append((23, "Closed", "Telnet"))
        scanner.scan_results.append((80, "Open", "HTTP"))
        open_ports=scanner.get_open_ports()
        self.assertEqual(len(open_ports), 2)

    def test_common_ports_dict(self):
        self.assertEqual(common_ports[80], "HTTP")
        self.assertEqual(common_ports[22], "SSH")
    
    def test_invalid_target(self):
        scanner=PortScanner("127.0.0.1")
        scanner.target=""
        self.assertEqual(scanner.target, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
