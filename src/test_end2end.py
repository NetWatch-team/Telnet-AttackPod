"""
End-to-end tests for NetWatch Telnet AttackPod functions
"""

import unittest
import os
import sys
from unittest.mock import patch, MagicMock

# Add the src directory to path so we can import monitor
sys.path.insert(0, os.path.dirname(__file__))

class TestMonitorEndToEnd(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Clear any test environment variables
        test_vars = ['TEST_VAR', 'NETWATCH_TEST_MODE', 'NETWATCH_COLLECTOR_URL', 
                    'COLLECTOR_REQUEST_TIMEOUT', 'CHECK_IP_TIMEOUT', 'SENSOR_UUID',
                    'SENSOR_TLP', 'NETWATCH_COLLECTOR_AUTHORIZATION', 'ATTACK_POD_IP']
        for var in test_vars:
            if var in os.environ:
                del os.environ[var]
        
        # Reset any cached imports that might interfere with tests
        modules_to_remove = [key for key in sys.modules.keys() if key.startswith('monitor')]
        for module in modules_to_remove:
            del sys.modules[module]

    def tearDown(self):
        """Clean up after each test method.""" 
        # Ensure clean state after tests
        self.setUp()
    
    @patch('monitor.requests.get')
    def test_get_local_ip_success(self, mock_get):
        """Test successful IP detection with mocked API calls"""
        # Mock the response from the NetWatch API
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'ip': '203.0.113.42'}
        mock_get.return_value = mock_response
        
        from monitor import get_local_ip
        
        # Test with default URL (should use the mocked response)
        ip = get_local_ip()
        self.assertEqual(ip, '203.0.113.42')
        
    def test_attack_submission_structure(self):
        """Test that attack submission produces correct structure"""
        from monitor import submit_attack, is_private_ip
        
        # Make sure we test public IP for source - it should not be filtered out
        self.assertFalse(is_private_ip("8.8.8.8"))  # This should be false
        
        # Mock the queue to capture what gets submitted  
        with patch('monitor.attack_queue') as mock_queue:
            # Test with public IPs (should go through)
            submit_attack(
                ip='8.8.8.8',  # Public IP 
                user='testuser',
                password='testpass',
                evidence='Test attack',
                ATTACKPOD_LOCAL_IP='203.0.113.42',  # Public IP - not private 
                source_port=12345
            )
            
            # Verify that queue.put was called with correct data  
            self.assertTrue(mock_queue.put.called)
            
            # Get the arguments passed to put
            call_args = mock_queue.put.call_args[0][0]
            
            # Check structure of the data  
            self.assertIn('timestamp', call_args)
            self.assertIn('uuid', call_args)
            self.assertIn('source', call_args)
            self.assertIn('destination', call_args)
            self.assertIn('attack_type', call_args)
            self.assertIn('metadata', call_args)
            self.assertEqual(call_args['source'], '8.8.8.8')
            self.assertEqual(call_args['destination'], '203.0.113.42')
            
            # Check metadata structure
            self.assertIn('username', call_args['metadata'])
            self.assertIn('password', call_args['metadata'])
            self.assertIn('source_port', call_args['metadata'])
            self.assertEqual(call_args['metadata']['username'], 'testuser')
            self.assertEqual(call_args['metadata']['password'], 'testpass')
            self.assertEqual(call_args['metadata']['source_port'], 12345)
            
    def test_attack_submission_filtered_private_ips(self):
        """Test that attack submission correctly filters out private IPs"""
        from monitor import submit_attack
        
        # Mock the queue to capture what gets submitted
        with patch('monitor.attack_queue') as mock_queue:
            # Test with private IP (should be filtered out)
            # Using 192.168.1.100 as source, which is private
            submit_attack(
                ip='192.168.1.100',
                user='testuser',
                password='testpass',
                evidence='Test attack',
                ATTACKPOD_LOCAL_IP='8.8.8.8',
                source_port=12345
            )
            
            # Verify that queue.put was NOT called (private IP should be filtered)
            self.assertFalse(mock_queue.put.called)
    
    def test_private_ip_detection(self):
        """Test private IP address detection works correctly"""
        from monitor import is_private_ip
        
        # Test private IPs (these should be detected as private)
        private_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1', '127.0.0.1']
        for ip in private_ips:
            self.assertTrue(is_private_ip(ip), f"IP {ip} should be detected as private")
        
        # Test public IPs (these should NOT be detected as private)
        public_ips = ['8.8.8.8', '1.1.1.1']
        for ip in public_ips:
            self.assertFalse(is_private_ip(ip), f"IP {ip} should not be detected as private")
    
    def test_environment_variables_loading(self):
        """Test that environment variables are properly loaded"""
        from monitor import get_env
        
        # Test with environment variable set
        os.environ['TEST_VAR'] = 'test_value'
        result = get_env('TEST_VAR', 'default')
        self.assertEqual(result, 'test_value')
        
        # Test with no variable set (should return default)
        result = get_env('NONEXISTENT_VAR', 'default_value')
        self.assertEqual(result, 'default_value')
    
    def test_test_mode_detection(self):
        """Test that test mode detection works correctly"""
        from monitor import _check_if_in_test_mode
        
        # Test with no environment variable (should be False)
        result = _check_if_in_test_mode()
        self.assertFalse(result)
        
        # Test with explicit test mode
        os.environ['NETWATCH_TEST_MODE'] = 'true'
        result = _check_if_in_test_mode()
        self.assertTrue(result)

if __name__ == '__main__':
    unittest.main()