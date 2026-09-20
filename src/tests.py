"""
Tests for NetWatch Telnet AttackPod functions
"""

import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Add the src directory to path so we can import monitor
sys.path.insert(0, os.path.dirname(__file__))

# Mock the get_env function at module level to avoid circular imports during testing
def mock_get_env(key, fallback):
    return os.environ.get(key, fallback)

# Temporarily replace get_env for testing
import sys
sys.path.insert(0, os.path.dirname(__file__))
import monitor
original_get_env = monitor.get_env
monitor.get_env = mock_get_env

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
        # Test with environment variable set
        os.environ['TEST_VAR'] = 'test_value'
        result = monitor.get_env('TEST_VAR', 'fallback')
        self.assertEqual(result, 'test_value')
        
        # Test with environment variable not set (should return fallback)
        result = monitor.get_env('NONEXISTENT_VAR', 'fallback')
        self.assertEqual(result, 'fallback')
    
    def test_check_if_in_test_mode(self):
        """Test test mode detection"""
        # Test with test mode enabled
        os.environ['NETWATCH_TEST_MODE'] = 'true'
        self.assertTrue(monitor._check_if_in_test_mode())
        
        # Test with test mode disabled
        os.environ['NETWATCH_TEST_MODE'] = 'false'
        self.assertFalse(monitor._check_if_in_test_mode())
        
        # Test default (should be false)
        if 'NETWATCH_TEST_MODE' in os.environ:
            del os.environ['NETWATCH_TEST_MODE']
        self.assertFalse(monitor._check_if_in_test_mode())
    
    def test_is_private_ip(self):
        """Test private IP address detection"""
        # Test private IP addresses (should return True)
        private_ips = [
            '10.0.0.1',
            '172.16.0.1',
            '192.168.1.1', 
            '127.0.0.1',
            '169.254.1.1'
        ]
        
        for ip in private_ips:
            self.assertTrue(monitor.is_private_ip(ip), f"Expected {ip} to be private")
            
        # Test public IP addresses (should return False)
        public_ips = [
            '8.8.8.8',
            '1.1.1.1',
            '203.0.113.42'
        ]
        
        for ip in public_ips:
            self.assertFalse(monitor.is_private_ip(ip), f"Expected {ip} to be public")
            
        # Test invalid IP address (should return False)
        self.assertFalse(monitor.is_private_ip('invalid-ip'))
    
    @patch('monitor.requests.get')
    def test_get_local_ip_success(self, mock_get):
        """Test successful IP detection"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'ip': '203.0.113.42'}
        mock_get.return_value = mock_response
        
        # Test with default URL
        ip = monitor.get_local_ip()
        self.assertEqual(ip, '203.0.113.42')
        
    @patch('monitor.requests.get')
    def test_get_local_ip_failure(self, mock_get):
        """Test IP detection failure handling"""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        
        # Mock the exit function to avoid actual exit during testing
        with patch('monitor.exit') as mock_exit:
            # This should call exit when all retries are exhausted
            monitor.get_local_ip()
            mock_exit.assert_called_once()

if __name__ == '__main__':
    # Restore original get_env before running tests
    monitor.get_env = original_get_env
    unittest.main()