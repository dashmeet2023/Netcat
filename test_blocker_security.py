import unittest
import sys
import os

# Add workspace directory to python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netcat.blocker import BlockManager
from netcat.config_manager import ConfigManager
from netcat.database import DatabaseManager

class TestBlockerSecurity(unittest.TestCase):
    def setUp(self):
        # Create a mock config and database manager
        self.config = ConfigManager()
        self.db = DatabaseManager(db_path="test_security.db")
        self.block_manager = BlockManager(self.config, self.db)

    def tearDown(self):
        # Stop blocker thread if running and clean up database
        self.block_manager.shutdown()
        if os.path.exists("test_security.db"):
            try:
                os.remove("test_security.db")
            except Exception:
                pass

    def test_valid_ip_blocking(self):
        # Test valid IPv4 address blocking (should return True or False but not raise ValueError)
        ip = "198.51.100.4"
        try:
            res = self.block_manager.block_ip(ip, reason="Test Valid IP")
            self.assertIn(res, [True, False])
        except ValueError:
            self.fail("Valid IP raised ValueError")

    def test_injection_ips(self):
        # List of invalid / command-injection IPs to test
        bad_ips = [
            "1.1.1.1\" & calc.exe & \"",
            "1.2.3.4; format c:",
            "192.168.1.100 | notepad.exe",
            "invalid_ip_format",
            "256.100.50.25",
            "",
            "1.1.1.1\ncalc.exe",
        ]
        
        for ip in bad_ips:
            with self.assertRaises(ValueError, msg=f"Failed to raise ValueError for injection payload: {ip}"):
                self.block_manager.block_ip(ip, reason="Test Injection IP")

            with self.assertRaises(ValueError, msg=f"Failed to raise ValueError for injection payload on unblock: {ip}"):
                self.block_manager.unblock_ip(ip, reason="Test Injection IP")

    def test_windivert_filter_cleanliness(self):
        # Inject an invalid IP directly into self.active_blocks to test if it gets bypassed by windivert filter generator
        # bypassing the validate path to ensure defense-in-depth in _get_windivert_filter
        self.block_manager.active_blocks["1.1.1.1\" & calc.exe"] = {
            "timestamp": 0,
            "backend": "windivert",
            "reason": "Direct Injection Test",
            "expire_timer": None
        }
        self.block_manager.active_blocks["192.0.2.1"] = {
            "timestamp": 0,
            "backend": "windivert",
            "reason": "Valid Test",
            "expire_timer": None
        }
        
        filter_str = self.block_manager._get_windivert_filter()
        # Verify that the invalid IP did not get concatenated into the filter string
        self.assertNotIn("calc.exe", filter_str)
        self.assertIn("192.0.2.1", filter_str)

if __name__ == "__main__":
    unittest.main()
