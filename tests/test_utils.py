"""
Unit tests for utility modules
"""

import unittest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from utils.network_utils import validate_target, parse_port_range, is_valid_ip

class TestNetworkUtils(unittest.TestCase):
    """Test network utility functions"""
    
    def test_is_valid_ip(self):
        """Test IP address validation"""
        self.assertTrue(is_valid_ip("192.168.1.1"))
        self.assertTrue(is_valid_ip("127.0.0.1"))
        self.assertTrue(is_valid_ip("::1"))
        self.assertFalse(is_valid_ip("256.1.1.1"))
        self.assertFalse(is_valid_ip("invalid"))
    
    def test_parse_port_range_single(self):
        """Test single port parsing"""
        ports = parse_port_range("80")
        self.assertEqual(ports, [80])
    
    def test_parse_port_range_range(self):
        """Test port range parsing"""
        ports = parse_port_range("80-85")
        self.assertEqual(ports, [80, 81, 82, 83, 84, 85])
    
    def test_parse_port_range_list(self):
        """Test port list parsing"""
        ports = parse_port_range("80,443,8080")
        self.assertEqual(sorted(ports), [80, 443, 8080])
    
    def test_parse_port_range_invalid(self):
        """Test invalid port range"""
        with self.assertRaises(ValueError):
            parse_port_range("80-70")  # Invalid range
        
        with self.assertRaises(ValueError):
            parse_port_range("99999")  # Port too high
    
    def test_validate_target_ip(self):
        """Test target validation with IP"""
        targets = validate_target("127.0.0.1")
        self.assertEqual(targets, ["127.0.0.1"])
    
    def test_validate_target_cidr(self):
        """Test target validation with CIDR"""
        targets = validate_target("192.168.1.0/30")
        self.assertEqual(len(targets), 2)  # .1 and .2
        self.assertIn("192.168.1.1", targets)
        self.assertIn("192.168.1.2", targets)

if __name__ == '__main__':
    unittest.main()
