"""
Additional tests for NetWatch Telnet AttackPod functions
"""

import unittest
import os
import sys
from unittest.mock import patch, MagicMock

# Add the src directory to path so we can import monitor
sys.path.insert(0, os.path.dirname(__file__))

class TestMonitorAdvancedFunctions(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Clear any test environment variables
        test_vars = ['TEST_VAR', 'NETWATCH_TEST_MODE', 'NETWATCH_COLLECTOR_URL', 
                    'COLLECTOR_REQUEST_TIMEOUT', 'CHECK_IP_TIMEOUT']
        for var in test_vars:
            if var in os.environ:
                del os.environ[var]
    
    def tearDown(self):
        """Clean up after each test method.""" 
        # Ensure clean state after tests
        self.setUp()
    
    @patch('monitor.requests.get')
    def test_get_local_ip_success(self, mock_get):
        """Test successful IP detection"""
        # Mock the response from the NetWatch API
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'ip': '203.0.113.42'}
        mock_get.return_value = mock_response
        
        # Import after setting environment
        from monitor import get_local_ip
        
        # Test with default URL (should use the mocked response)
        ip = get_local_ip()
        self.assertEqual(ip, '203.0.113.42')
        
    @patch('monitor.time.sleep')
    @patch('monitor.requests.get')
    def test_get_local_ip_failure(self, mock_get, mock_sleep):
        """Test IP detection failure handling"""
        # Mock a failed response from the API
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        
        # Import after setting environment
        from monitor import get_local_ip
        
        # Mock sys.exit to avoid actual program termination during testing
        with patch('monitor.sys.exit') as mock_exit:
            mock_exit.side_effect = SystemExit(1)
            # This should call sys.exit when all retries are exhausted
            with self.assertRaises(SystemExit):
                get_local_ip(max_retries=2, retry_delay=0)
            mock_exit.assert_called_once_with(1)


if __name__ == '__main__':
    unittest.main()