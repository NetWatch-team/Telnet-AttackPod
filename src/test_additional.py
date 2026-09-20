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

    def test_handle_client_releases_semaphore(self):
        """Test that handle_client always releases the semaphore"""
        import threading
        from monitor import handle_client
        
        sem = threading.BoundedSemaphore(1)
        self.assertTrue(sem.acquire(blocking=False))
        
        mock_socket = MagicMock()
        mock_socket.recv.return_value = b""
        
        handle_client(mock_socket, "1.2.3.4", semaphore=sem)
        # Verify semaphore was released back
        self.assertTrue(sem.acquire(blocking=False))

    def test_filter_telnet_iac(self):
        """Test RFC 854 IAC filtering logic"""
        from monitor import filter_telnet_iac
        
        # Test basic text without commands
        clean, rem = filter_telnet_iac(b"admin\r\n")
        self.assertEqual(clean, bytearray(b"admin\r\n"))
        self.assertEqual(rem, b"")
        
        # Test 3-byte WILL / WONT command stripping
        clean, rem = filter_telnet_iac(b"\xff\xfb\x01user\r\n")
        self.assertEqual(clean, bytearray(b"user\r\n"))
        self.assertEqual(rem, b"")
        
        # Test escaped IAC (0xFF 0xFF -> 0xFF)
        clean, rem = filter_telnet_iac(b"\xff\xff")
        self.assertEqual(clean, bytearray(b"\xff"))
        self.assertEqual(rem, b"")
        
        # Test subnegotiation stripping (IAC SB ... IAC SE)
        clean, rem = filter_telnet_iac(b"\xff\xfa\x18\x00VT100\xff\xf0pass\r\n")
        self.assertEqual(clean, bytearray(b"pass\r\n"))
        self.assertEqual(rem, b"")
        
        # Test trailing incomplete IAC byte
        clean, rem = filter_telnet_iac(b"abc\xff")
        self.assertEqual(clean, bytearray(b"abc"))
        self.assertEqual(rem, b"\xff")

    def test_telnet_read_filtered_input_buffering_and_caps(self):
        """Test buffered line reading and max length capping"""
        from monitor import telnet_read_filtered_input
        
        mock_socket = MagicMock()
        # Simulate fragmented chunk delivery across two packets
        mock_socket.recv.side_effect = [b"root", b"admin\r\n"]
        result = telnet_read_filtered_input(mock_socket, max_length=50)
        self.assertEqual(result, "rootadmin")
        
        # Test length capping
        mock_socket.recv.side_effect = [b"A" * 100 + b"\r\n"]
        result = telnet_read_filtered_input(mock_socket, max_length=10)
        self.assertEqual(len(result), 10)
        self.assertEqual(result, "A" * 10)


if __name__ == '__main__':
    unittest.main()