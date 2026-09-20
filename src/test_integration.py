"""
Integration tests for NetWatch Telnet AttackPod
"""

import unittest
import os
import sys
import json
from unittest.mock import patch, MagicMock

# Add the src directory to path so we can import monitor
sys.path.insert(0, os.path.dirname(__file__))

class TestMonitorIntegration(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Clear any environment variables that might affect testing
        test_vars = ['TEST_VAR', 'NETWATCH_TEST_MODE', 'NETWATCH_COLLECTOR_URL', 
                    'COLLECTOR_REQUEST_TIMEOUT', 'CHECK_IP_TIMEOUT', 'SENSOR_UUID',
                    'SENSOR_TLP', 'NETWATCH_COLLECTOR_AUTHORIZATION']
        for var in test_vars:
            if var in os.environ:
                del os.environ[var]
        
        # Reset any cached imports that might interfere with tests
        if 'monitor' in sys.modules:
            del sys.modules['monitor']

    def tearDown(self):
        """Clean up after each test method.""" 
        # Ensure clean state after tests
        self.setUp()
    
    def test_environment_variable_loading(self):
        """Test that environment variables are properly loaded"""
        # Set some test variables
        os.environ['TEST_VAR'] = 'test_value'
        
        from monitor import get_env
        
        # Test with existing variable
        result = get_env('TEST_VAR', 'default')
        self.assertEqual(result, 'test_value')
        
        # Test with non-existing variable (should return default)
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
    
    def test_private_ip_detection(self):
        """Test private IP address detection works correctly"""
        from monitor import is_private_ip
        
        # Test private IPs (these should be detected as private)
        private_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1', '127.0.0.1']
        for ip in private_ips:
            self.assertTrue(is_private_ip(ip), f"IP {ip} should be detected as private")
        
        # Test public IPs (these should NOT be detected as private)
        public_ips = ['8.8.8.8', '1.1.1.1', '203.0.113.42']
        for ip in public_ips:
            self.assertFalse(is_private_ip(ip), f"IP {ip} should not be detected as private")
    
    def test_get_local_ip_imports(self):
        """Test that get_local_ip can be imported without issues"""
        from monitor import get_local_ip
        
        # Just verify it imports - actual function execution would need network
        self.assertTrue(callable(get_local_ip))
        
    @patch('monitor.requests.get')
    def test_get_local_ip_failure_handling(self, mock_get):
        """Test that get_local_ip handles API failures correctly"""
        # Mock a failed response from the API
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        
        with patch('monitor.logging') as mock_logging:
            # This should not actually call exit in our test environment
            try:
                from monitor import get_local_ip
                # Should return None or raise exception during testing
                ip = get_local_ip()
            except Exception:
                pass  # Expected behavior
    
    def test_attack_submission_structure(self):
        """Test that attack submission produces correct structure"""
        from monitor import submit_attack, _check_if_in_test_mode, is_private_ip
        
        # Mock the queue to capture what gets submitted
        with patch('monitor.attack_queue') as mock_queue:
            # Test with public IPs (should be processed)
            submit_attack(
                ip='203.0.113.42',
                user='testuser',
                password='testpass',
                evidence='Test attack',
                ATTACKPOD_LOCAL_IP='8.8.8.8',
                source_port=12345
            )
            
            # Verify that queue.put was called with correct data
            self.assertTrue(mock_queue.put.called)
            
            # Get the arguments passed to put
            call_args = mock_queue.put.call_args[0][0]  # First argument of the call
            
            # Check structure of the data
            self.assertIn('timestamp', call_args)
            self.assertIn('uuid', call_args)
            self.assertIn('source', call_args)
            self.assertIn('destination', call_args)
            self.assertIn('attack_type', call_args)
            self.assertIn('metadata', call_args)
            self.assertEqual(call_args['source'], '203.0.113.42')
            self.assertEqual(call_args['destination'], '8.8.8.8')
    
    def test_attack_forward_worker_structure(self):
        """Test that attack forward worker handles configuration correctly"""
        from monitor import get_env, _check_if_in_test_mode
        
        # Test environment configuration loading
        test_url = get_env("NETWATCH_COLLECTOR_URL", "https://api.netwatch.org")
        self.assertEqual(test_url, "https://api.netwatch.org")
        
        # Test with custom environment variable
        os.environ["NETWATCH_COLLECTOR_URL"] = "https://custom.netwatch.org"
        test_url = get_env("NETWATCH_COLLECTOR_URL", "https://api.netwatch.org")
        self.assertEqual(test_url, "https://custom.netwatch.org")


if __name__ == '__main__':
    unittest.main()