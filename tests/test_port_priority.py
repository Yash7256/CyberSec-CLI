"""
Unit tests for the port priority module.
"""

import unittest

from core.port_priority import PRIORITY_PORTS, get_priority_for_port, get_scan_order


class TestPortPriority(unittest.TestCase):

    def test_get_scan_order_basic(self):
        """Test basic functionality of get_scan_order."""
        ports = [21, 22, 80, 443, 3306, 1000, 2000]
        result = get_scan_order(ports)

        # Should have 4 groups: critical, high, medium, low
        self.assertEqual(len(result), 4)

        # Check that critical ports are in the first group
        self.assertIn(21, result[0])  # FTP
        self.assertIn(22, result[0])  # SSH
        self.assertIn(80, result[0])  # HTTP
        self.assertIn(443, result[0])  # HTTPS
        self.assertIn(3306, result[0])  # MySQL

        # Check that non-priority ports are in the low group
        self.assertIn(1000, result[3])
        self.assertIn(2000, result[3])

    def test_get_scan_order_empty(self):
        """Test get_scan_order with empty input."""
        result = get_scan_order([])
        self.assertEqual(result, [[], [], [], []])

    def test_get_scan_order_no_critical(self):
        """Test get_scan_order with no critical ports."""
        ports = [1000, 2000, 9999]
        result = get_scan_order(ports)

        # All ports should be in the low priority group
        self.assertEqual(result[0], [])  # Critical
        self.assertEqual(result[1], [])  # High
        self.assertEqual(result[2], [])  # Medium
        self.assertEqual(set(result[3]), {1000, 2000, 9999})  # Low

    def test_get_scan_order_mixed(self):
        """Test get_scan_order with mixed priority ports."""
        ports = [21, 22, 53, 135, 1000, 3306, 8080]
        result = get_scan_order(ports)

        # Critical ports
        self.assertEqual(set(result[0]), {21, 22, 3306, 8080})

        # High ports
        self.assertEqual(set(result[1]), {53})

        # Medium ports
        self.assertEqual(set(result[2]), {135})

        # Low ports
        self.assertEqual(set(result[3]), {1000})

    def test_get_priority_for_port(self):
        """Test get_priority_for_port function."""
        # Test critical ports
        self.assertEqual(get_priority_for_port(21), "critical")  # FTP
        self.assertEqual(get_priority_for_port(22), "critical")  # SSH
        self.assertEqual(get_priority_for_port(80), "critical")  # HTTP
        self.assertEqual(get_priority_for_port(443), "critical")  # HTTPS

        # Test high ports
        self.assertEqual(get_priority_for_port(53), "high")  # DNS
        self.assertEqual(get_priority_for_port(110), "high")  # POP3

        # Test medium ports
        self.assertEqual(get_priority_for_port(135), "medium")  # MS RPC
        self.assertEqual(get_priority_for_port(139), "medium")  # NetBIOS

        # Test low ports
        self.assertEqual(get_priority_for_port(1000), "low")
        self.assertEqual(get_priority_for_port(2000), "low")

    def test_priority_port_definitions(self):
        """Test that priority port definitions are correct."""
        # Check that critical ports are defined correctly
        critical_expected = {21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080, 8443}
        self.assertEqual(PRIORITY_PORTS["critical"], critical_expected)

        # Check that high ports are defined correctly
        high_expected = {20, 53, 110, 143, 445, 1433, 1521, 3000, 5000, 8000, 27017}
        self.assertEqual(PRIORITY_PORTS["high"], high_expected)

        # Check that medium ports are defined correctly
        medium_expected = {135, 139, 389, 636, 1723, 2049, 5900, 6379, 9200, 11211}
        self.assertEqual(PRIORITY_PORTS["medium"], medium_expected)


if __name__ == "__main__":
    unittest.main()
