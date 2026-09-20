"""
Simplified test file for NetWatch Telnet AttackPod functions
"""

import unittest
import os
import sys

# Add the src directory to path so we can import monitor
sys.path.insert(0, os.path.dirname(__file__))

class TestMonitorFunctions(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Clear any test environment variables
        test_vars = ['TEST_VAR', 'NETWATCH_TEST_MODE']
        for var in test_vars:
            if var in os.environ:
                del os.environ[var]
    
    def tearDown(self):
        """Clean up after each test method.""" 
        # Ensure clean state after tests
        self.setUp()
    
    def test_get_env_with_fallback(self):
        """Test get_env function with fallback values"""
        # Import after setting up path and clearing environment
        from monitor import get_env
        
        # Test with environment variable set
        os.environ['TEST_VAR'] = 'test_value'
        result = get_env('TEST_VAR', 'fallback')
        self.assertEqual(result, 'test_value')
        
        # Test with environment variable not set (should return fallback)
        result = get_env('NONEXISTENT_VAR', 'fallback')
        self.assertEqual(result, 'fallback')

    def test_check_if_in_test_mode(self):
        """Test test mode detection"""
        # Import after setting up path and clearing environment
        from monitor import _check_if_in_test_mode
        
        # Test with test mode enabled
        os.environ['NETWATCH_TEST_MODE'] = 'true'
        self.assertTrue(_check_if_in_test_mode())
        
        # Test with test mode disabled
        os.environ['NETWATCH_TEST_MODE'] = 'false'
        self.assertFalse(_check_if_in_test_mode())
        
        # Test default (should be false)
        if 'NETWATCH_TEST_MODE' in os.environ:
            del os.environ['NETWATCH_TEST_MODE']
        self.assertFalse(_check_if_in_test_mode())

    def test_is_private_ip(self):
        """Test private IP address detection"""
        # Import after setting up path and clearing environment
        from monitor import is_private_ip
        
        # Test private IP addresses (should return True)
        private_ips = [
            '10.0.0.1',
            '172.16.0.1',
            '192.168.1.1', 
            '127.0.0.1',
            '169.254.1.1'
        ]
        
        for ip in private_ips:
            self.assertTrue(is_private_ip(ip), f"Expected {ip} to be private")
            
        # Test public IP addresses (should return False)
        # These example addresses need to be different ones that are truly public
        public_ips = [
            '8.8.8.8',
            '1.1.1.1'
        ]
        
        for ip in public_ips:
            self.assertFalse(is_private_ip(ip), f"Expected {ip} to be public")
            
        # Test invalid IP address (should return False)
        self.assertFalse(is_private_ip('invalid-ip'))

if __name__ == '__main__':
    unittest.main()