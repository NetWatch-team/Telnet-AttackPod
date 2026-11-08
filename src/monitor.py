"""
NetWatch Telnet AttackPod

AttackPod that captures Telnet brute-force login attempts and reports them to
the NetWatch backend for abuse mitigation and notification.

This sensor listens on port 23 (mapped from internal port 2323) and presents
a fake Telnet login prompt. All credentials and source IPs are captured and
forwarded to the central NetWatch backend for processing.
"""

import hashlib
import ipaddress
import logging
import os
import queue
import random
import re
import signal
import socket
import sys
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Tuple

import requests

# Global shutdown event to coordinate graceful termination
shutdown_event = threading.Event()

# ============================================================================
# CONFIGURATION CONSTANTS
# ============================================================================

# NetWatch Collector Configuration
DEFAULT_COLLECTOR_URL = "https://api.netwatch.team"
COLLECTOR_REQUEST_TIMEOUT = int(os.getenv("COLLECTOR_REQUEST_TIMEOUT", "10"))  # seconds for API requests
CHECK_IP_TIMEOUT = int(os.getenv("CHECK_IP_TIMEOUT", "5"))  # seconds for IP check requests

# IP Detection Configuration
MAX_IP_RETRY_ATTEMPTS = int(os.getenv("MAX_IP_RETRY_ATTEMPTS", "50"))  # max attempts to get local IP
IP_RETRY_DELAY_SECONDS = int(os.getenv("IP_RETRY_DELAY_SECONDS", "10"))  # delay between IP detection retries

# Telnet Server Configuration
TELNET_INTERNAL_PORT = int(os.getenv("TELNET_INTERNAL_PORT", "2323"))  # non-privileged port inside Docker
TELNET_LISTEN_BACKLOG = int(os.getenv("TELNET_LISTEN_BACKLOG", "100"))  # max queued connections
CLIENT_TIMEOUT_SECONDS = int(os.getenv("CLIENT_TIMEOUT_SECONDS", "30"))  # timeout for client connections
MAX_CONCURRENT_CLIENTS = int(os.getenv("MAX_CONCURRENT_CLIENTS", "100"))  # max concurrent client connections

# Telnet Protocol Constants
TELNET_IAC = int(os.getenv("TELNET_IAC", "255"))  # Interpret As Command byte (0xFF)
TELNET_DONT = 254
TELNET_DO = 253
TELNET_WONT = 252
TELNET_WILL = 251
TELNET_SB = 250  # Subnegotiation Begin
TELNET_SE = 240  # Subnegotiation End
TELNET_COMMAND_LENGTH = int(os.getenv("TELNET_COMMAND_LENGTH", "3"))  # Standard option negotiation command length

# Input Processing Configuration
MAX_INPUT_RETRIES = int(os.getenv("MAX_INPUT_RETRIES", "30"))  # max attempts to read username/password
INPUT_RETRY_DELAY = float(os.getenv("INPUT_RETRY_DELAY", "0.1"))  # delay between empty input retries (seconds)
SOCKET_RECV_BUFFER = int(os.getenv("SOCKET_RECV_BUFFER", "1024"))  # bytes to read at once
MAX_INPUT_LENGTH = int(os.getenv("MAX_INPUT_LENGTH", "256"))  # max chars allowed for username/password
MAX_QUEUE_SIZE = int(os.getenv("MAX_QUEUE_SIZE", "10000"))  # max pending attack submissions

# ============================================================================
# GLOBAL STATE
# ============================================================================

# Thread-safe bounded queue for attacks pending submission to NetWatch
attack_queue: queue.Queue[Dict[str, Any]] = queue.Queue(maxsize=MAX_QUEUE_SIZE)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================


def get_env(key: str, fallback: str) -> str:
    """
    Get an environment variable with a fallback default value.

    Args:
        key: Environment variable name
        fallback: Default value if variable is not set

    Returns:
        Environment variable value or fallback
    """
    return os.getenv(key, default=fallback)


def mask_sensitive_value(value: str) -> str:
    """
    Mask sensitive values (such as passwords) for secure logging.

    Reveals only first and last characters when length is sufficient,
    masking the rest to prevent cleartext exposure in logs.
    """
    if not value:
        return "(empty)"
    if len(value) <= 2:
        return "***"
    return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"


def _check_if_in_test_mode() -> bool:
    """
    Check if the sensor is running in test mode.

    In test mode, attacks are submitted to the backend but marked as test data
    and not processed for abuse notifications.

    Returns:
        True if test mode is enabled, False otherwise
    """
    return get_env("NETWATCH_TEST_MODE", "false").lower() == "true"


def validate_configuration() -> None:
    """
    Validate critical environment variables at startup and log warnings if missing.
    """
    auth_token = get_env("NETWATCH_COLLECTOR_AUTHORIZATION", "")
    if not auth_token or auth_token == "<API_KEY_FROM_NETWATCH_TEAM>":
        logging.warning(
            "[!] WARNING: NETWATCH_COLLECTOR_AUTHORIZATION is not configured. "
            "Attacks will fail to submit to the NetWatch collector API."
        )

    uuid = get_env("SENSOR_UUID", "")
    if not uuid or uuid == "your-unique-uuid-here":
        logging.warning("[!] WARNING: SENSOR_UUID is not configured or using placeholder value.")


# Private and non-routable network ranges per RFC 1918 and related standards
PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is private/non-routable per RFC 1918 and related standards.

    This includes:
    - RFC 1918 Private Networks: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    - Loopback Addresses: 127.0.0.0/8, ::1/128
    - Link-Local Addresses: 169.254.0.0/16, fe80::/10
    - Unique Local IPv6: fc00::/7

    Args:
        ip: IP address string to check

    Returns:
        True if IP is private/non-routable, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in PRIVATE_NETWORKS)
    except ValueError:
        logging.warning(f"Invalid IP address format: {ip}")
        return False


def get_local_ip(max_retries: int = MAX_IP_RETRY_ATTEMPTS, retry_delay: float = IP_RETRY_DELAY_SECONDS) -> str:
    """
    Detect the public IP address of this sensor by querying the NetWatch API.

    This function retries multiple times with delays to handle transient
    network issues during startup. If the IP cannot be determined after
    all retries, the program exits.

    Args:
        max_retries: Maximum number of detection attempts before giving up.
        retry_delay: Delay in seconds between retries.

    Returns:
        Public IP address as a string

    Raises:
        SystemExit: If IP cannot be detected after max retries
    """
    url = f"{get_env('NETWATCH_COLLECTOR_URL', DEFAULT_COLLECTOR_URL)}/check_ip"

    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=CHECK_IP_TIMEOUT)
            if response.status_code == 200:
                local_ip = response.json().get("ip")
                logging.info(f"[+] Detected public IP: {local_ip}")
                return local_ip
            else:
                logging.warning(f"[!] Attempt {attempt + 1}/{max_retries}: API returned status {response.status_code}")
        except requests.exceptions.RequestException as e:
            logging.error(f"[!] Attempt {attempt + 1}/{max_retries}: Error getting local IP: {e}")

        # Don't sleep after the last failed attempt
        if attempt < max_retries - 1:
            time.sleep(retry_delay)

    logging.error("[!] Unable to get local IP after all retries. Exiting.")
    sys.exit(1)


# ============================================================================
# ATTACK SUBMISSION
# ============================================================================


def submit_attack(
    ip: str,
    user: str,
    password: str,
    evidence: str,
    ATTACKPOD_LOCAL_IP: str,
    source_port: int,
    telnet_iac: str | None = None,
    telnet_iac_fingerprint: str | None = None,
    telnet_ttype: str | None = None,
    telnet_env: Dict[str, Any] | None = None,
    initial_command: str | None = None,
    busybox_token: str | None = None,
    payload_url: str | None = None,
) -> None:
    """
    Submit a captured attack to the queue for forwarding to NetWatch backend.

    This function filters out attacks from/to private IP addresses to prevent
    false positives and reduce backend processing load. Attacks involving
    RFC 1918 addresses, loopback, or link-local addresses are logged but not
    submitted.
    """
    # Filter out attacks involving private/local IPs
    if is_private_ip(ip) or is_private_ip(ATTACKPOD_LOCAL_IP):
        logging.info(
            f"[FILTERED] Skipping attack from/to private IP - "
            f"Source: {ip}, Destination: {ATTACKPOD_LOCAL_IP}, User: {user}"
        )
        return

    metadata: Dict[str, Any] = {
        "username": user,
        "password": password,
        "source_port": source_port,
    }
    if telnet_iac:
        metadata["telnet_iac"] = telnet_iac
    if telnet_iac_fingerprint:
        metadata["telnet_iac_fingerprint"] = telnet_iac_fingerprint
    if telnet_ttype:
        metadata["telnet_ttype"] = telnet_ttype
    if telnet_env:
        metadata["telnet_env"] = telnet_env
    if initial_command:
        metadata["initial_command"] = initial_command
    if busybox_token:
        metadata["busybox_token"] = busybox_token
    if payload_url:
        metadata["payload_url"] = payload_url

    # Build attack payload according to NetWatch API specification
    json_dict: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "uuid": get_env("SENSOR_UUID", ""),
        "tlp": get_env("SENSOR_TLP", "CLEAR"),
        "source": ip,
        "destination": ATTACKPOD_LOCAL_IP,
        "attack_type": "TELNET_BRUTE_FORCE",
        "source_type": "IP",
        "test_mode": _check_if_in_test_mode(),
        "evidence": evidence,
        "metadata": metadata,
    }

    # Queue the attack for async submission (drop and log warning if queue is full)
    try:
        attack_queue.put(json_dict, block=False)
    except queue.Full:
        logging.warning(f"[!] Attack queue full ({MAX_QUEUE_SIZE} items). Dropping attack telemetry from {ip}")


def attack_forward_worker() -> None:
    """
    Background worker thread that forwards queued attacks to NetWatch collector.

    This function runs indefinitely, pulling attacks from the queue and
    submitting them via HTTP POST. It uses a persistent session for connection
    pooling and includes proper error handling for network failures.

    The worker runs as a daemon thread and will terminate when the main
    program exits.
    """
    # Use Session for connection pooling (more efficient than individual requests)
    session = requests.Session()
    # Set a User-Agent header for better identification
    session.headers.update(
        {
            "Authorization": get_env("NETWATCH_COLLECTOR_AUTHORIZATION", ""),
            "User-Agent": "NetWatch-Telnet-AttackPod/0.2",
        }
    )
    url = f"{get_env('NETWATCH_COLLECTOR_URL', DEFAULT_COLLECTOR_URL)}/v2/add_attack/telnet_bruteforce"

    logging.info("[+] Attack forwarding worker started")

    while not shutdown_event.is_set() or not attack_queue.empty():
        try:
            # Poll with timeout to periodically check shutdown_event
            json_dict = attack_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        try:
            response = session.post(url, json=json_dict, timeout=COLLECTOR_REQUEST_TIMEOUT)

            if response.status_code == 200:
                # Success - format log message based on test mode
                status = "TEST MODE (NOT SAVED)" if _check_if_in_test_mode() else "SUCCESS"
                logging.info(f"[{status}] Reported: {json_dict['source']} -> {json_dict['metadata']['username']}")
            else:
                # Non-200 status code from API
                logging.error(f"[!] API Error: {response.status_code} - {response.text[:200]}")

        except requests.exceptions.Timeout:
            logging.error(f"[!] Timeout forwarding attack from {json_dict.get('source', 'unknown')}")
        except requests.exceptions.RequestException as e:
            logging.error(f"[!] Network error forwarding attack from {json_dict.get('source', 'unknown')}: {e}")
        except Exception as e:
            # Catch-all for unexpected errors to prevent worker thread death
            logging.error(f"[!] Unexpected error in attack forwarding: {e}")
        finally:
            # Mark task as done regardless of success/failure
            # Note: Failed attacks are logged but not retried to prevent
            # memory exhaustion from persistent failures
            attack_queue.task_done()


# ============================================================================
# TELNET PROTOCOL HANDLING
# ============================================================================


def filter_telnet_iac(data: bytes, telemetry: Dict[str, Any] | None = None) -> Tuple[bytearray, bytes]:
    """
    Filter out Telnet IAC (Interpret As Command) sequences per RFC 854.
    Optionally extracts ordered IAC options, terminal type, and environment variables into telemetry dict.
    """
    clean_data = bytearray()
    i = 0
    n = len(data)

    verb_names = {
        TELNET_WILL: "WILL",
        TELNET_WONT: "WONT",
        TELNET_DO: "DO",
        TELNET_DONT: "DONT",
    }

    while i < n:
        if data[i] == TELNET_IAC:
            # If IAC is at the very end with no command byte, return as leftover
            if i + 1 >= n:
                return clean_data, data[i:]

            cmd = data[i + 1]
            if cmd == TELNET_IAC:
                # Escaped IAC (0xFF 0xFF) evaluates to literal 0xFF data
                clean_data.append(TELNET_IAC)
                i += 2
            elif cmd in (TELNET_WILL, TELNET_WONT, TELNET_DO, TELNET_DONT):
                # 3-byte command: IAC <verb> <option>
                if i + 2 >= n:
                    # Incomplete 3-byte command
                    return clean_data, data[i:]
                opt = data[i + 2]
                if telemetry is not None:
                    telemetry.setdefault("iac_options", []).append(f"{verb_names.get(cmd, str(cmd))}:{opt}")
                i += 3
            elif cmd == TELNET_SB:
                # Subnegotiation: IAC SB ... IAC SE
                # Look for terminating IAC SE (0xFF 0xF0)
                se_index = -1
                j = i + 2
                while j < n:
                    if data[j] == TELNET_IAC and j + 1 < n and data[j + 1] == TELNET_SE:
                        se_index = j + 1
                        break
                    j += 1
                if se_index != -1:
                    if telemetry is not None and j > i + 2:
                        sb_opt = data[i + 2]
                        sb_payload = data[i + 3 : se_index - 1]
                        if sb_opt == 24 and sb_payload:  # TTYPE
                            # Format: \x00 <ttype_string>
                            raw_val = sb_payload[1:] if sb_payload[0] == 0 else sb_payload
                            ttype_str = raw_val.decode("ascii", errors="ignore").strip()[:64]
                            if ttype_str:
                                telemetry["ttype"] = ttype_str
                        elif sb_opt in (36, 39) and sb_payload:  # ENVIRON / NEW-ENVIRON
                            env_str = sb_payload.decode("latin1", errors="ignore")
                            for m in re.finditer(
                                r"[\x00\x03]?([A-Za-z0-9_-]+)[\x01=]([^\x00\x01\x02\x03\r\n]{1,128})", env_str
                            ):
                                telemetry.setdefault("env", {})[m.group(1)] = m.group(2)
                    i = se_index + 1
                else:
                    # Incomplete subnegotiation, wait for more data
                    return clean_data, data[i:]
            else:
                # Other 2-byte commands (NOP, BREAK, IP, AO, AYT, EC, EL, GA)
                i += 2
        else:
            clean_data.append(data[i])
            i += 1

    return clean_data, b""


def telnet_read_filtered_input(
    client_socket: socket.socket,
    max_length: int = MAX_INPUT_LENGTH,
    telemetry: Dict[str, Any] | None = None,
) -> str:
    """
    Read a complete line from a Telnet socket, filtering out IAC command sequences
    and respecting maximum input length caps.
    """
    accumulated_clean = bytearray()
    iac_buffer = b""
    retries = 0

    while retries < MAX_INPUT_RETRIES and len(accumulated_clean) < max_length:
        try:
            raw_chunk = client_socket.recv(SOCKET_RECV_BUFFER)
            if not raw_chunk:
                break

            # Combine leftover incomplete IAC bytes with newly received chunk
            clean_chunk, iac_buffer = filter_telnet_iac(iac_buffer + raw_chunk, telemetry=telemetry)

            if clean_chunk:
                accumulated_clean.extend(clean_chunk)

                # Check for line completion (\r or \n)
                if b"\n" in clean_chunk or b"\r" in clean_chunk:
                    break
            else:
                # Only IAC commands received in this chunk
                retries += 1
                time.sleep(INPUT_RETRY_DELAY)

        except TimeoutError:
            break
        except Exception as e:
            logging.debug(f"Error reading from socket: {e}")
            break

    # Decode to UTF-8, strip whitespace and line endings, enforce max length cap
    decoded = accumulated_clean.decode("utf-8", errors="ignore").strip()
    return decoded[:max_length]


def handle_client(
    client_socket: socket.socket, ATTACKPOD_LOCAL_IP: str, semaphore: threading.BoundedSemaphore | None = None
) -> None:
    """
    Handle a single Telnet client connection.

    This function implements a fake Telnet login prompt that captures
    username and password attempts. The interaction mimics a real Telnet
    server to encourage attackers to submit credentials.

    Flow:
    1. Send Telnet negotiation sequences (WILL ECHO, WILL SUPPRESS GO AHEAD)
    2. Prompt for username and capture input
    3. Prompt for password and capture input
    4. Log and submit the attack to NetWatch
    5. Return a fake "Login incorrect" message

    Args:
        client_socket: Connected client socket
        ATTACKPOD_LOCAL_IP: This sensor's public IP address
        semaphore: Optional semaphore released when the connection finishes
    """
    client_socket.settimeout(CLIENT_TIMEOUT_SECONDS)
    telemetry: Dict[str, Any] = {}

    try:
        # Step 1: Send Telnet negotiation commands
        # WILL ECHO (0xFB 0x01) + WILL SUPPRESS GO AHEAD (0xFB 0x03)
        client_socket.sendall(b"\xff\xfb\x01\xff\xfb\x03")

        # Step 2: Capture Username
        client_socket.sendall(b"login: ")
        username = ""
        retry_count = 0

        # Keep reading until we get non-empty input (filtering out IAC sequences)
        while not username and retry_count < MAX_INPUT_RETRIES:
            username = telnet_read_filtered_input(client_socket, telemetry=telemetry)
            if not username:
                retry_count += 1
                time.sleep(INPUT_RETRY_DELAY)

        # If we couldn't get a username after retries, give up
        if not username:
            logging.debug("No username received after max retries")
            return

        # Step 3: Capture Password
        client_socket.sendall(b"Password: ")
        password = ""
        retry_count = 0

        while not password and retry_count < MAX_INPUT_RETRIES:
            password = telnet_read_filtered_input(client_socket, telemetry=telemetry)
            if not password:
                retry_count += 1
                time.sleep(INPUT_RETRY_DELAY)

        # If no password, still log what we got
        if not password:
            logging.debug("No password received after max retries")
            return

        # Step 4: Extract telemetry, capture staging command, and submit attack
        remote_ip, remote_port = client_socket.getpeername()
        masked_pwd = mask_sensitive_value(password)
        logging.info(f"[CAPTURE] {username} / {masked_pwd} from {remote_ip}:{remote_port}")

        iac_opts = telemetry.get("iac_options", [])
        telnet_iac_str = ",".join(iac_opts) if iac_opts else None
        telnet_iac_fp = (
            hashlib.md5(telnet_iac_str.encode("utf-8"), usedforsecurity=False).hexdigest() if telnet_iac_str else None
        )
        telnet_ttype = telemetry.get("ttype")
        telnet_env = telemetry.get("env")

        capture_first_command = get_env("TELNET_CAPTURE_FIRST_COMMAND", "true").lower() == "true"
        initial_command: str | None = None
        busybox_token: str | None = None
        payload_url: str | None = None

        if capture_first_command:
            try:
                client_socket.sendall(b"\r\nBusyBox v1.35.0 built-in shell (ash)\r\n# ")
                client_socket.settimeout(2.5)
                captured_lines: List[str] = []

                for _ in range(4):
                    cmd_line = telnet_read_filtered_input(client_socket, max_length=1024, telemetry=telemetry)
                    if not cmd_line:
                        break
                    captured_lines.append(cmd_line)
                    if cmd_line in ("enable", "system", "shell", "sh"):
                        client_socket.sendall(b"# ")
                        continue
                    else:
                        break

                if captured_lines:
                    initial_command = "; ".join(captured_lines)[:1024]
                    m_tok = re.search(r"/bin/busybox\s+([A-Za-z0-9_.-]+)", initial_command)
                    if m_tok:
                        busybox_token = m_tok.group(1)
                    m_url = re.search(
                        r"(?:https?|tftp)://[^\s;'\"]+|ftpget\s+[^\s;'\"]+\s+([^\s;'\"]+)", initial_command
                    )
                    if m_url:
                        payload_url = m_url.group(0)
            except Exception as e:
                logging.debug(f"Post-auth command capture finished/timed out: {e}")

        evidence = f"Telnet login attempt by username '{username}' from ip '{remote_ip}'"
        if initial_command:
            evidence += f" with command '{initial_command[:100]}'"

        submit_attack(
            ip=remote_ip,
            user=username,
            password=password,
            evidence=evidence,
            ATTACKPOD_LOCAL_IP=ATTACKPOD_LOCAL_IP,
            source_port=remote_port,
            telnet_iac=telnet_iac_str,
            telnet_iac_fingerprint=telnet_iac_fp,
            telnet_ttype=telnet_ttype,
            telnet_env=telnet_env,
            initial_command=initial_command,
            busybox_token=busybox_token,
            payload_url=payload_url,
        )

        # Step 5: Mimic real server behavior - delay and reject
        time.sleep(random.uniform(0.1, 0.4))  # Realistic processing delay # nosec B311
        try:
            client_socket.sendall(b"\r\nLogin incorrect\r\n\r\n")
        except Exception:
            pass

    except TimeoutError:
        logging.debug("Client connection timed out")
    except ConnectionResetError:
        logging.debug("Client connection reset")
    except Exception as e:
        logging.debug(f"Client handler error: {e}")
    finally:
        # Always close the socket
        try:
            client_socket.close()
        except Exception:
            pass
        if semaphore:
            semaphore.release()


# ============================================================================
# SERVER MAIN LOOP
# ============================================================================


def start_telnet_server(local_ip: str, max_clients: int = MAX_CONCURRENT_CLIENTS) -> None:
    """
    Start the main Telnet server loop.

    This function creates a socket server that listens for incoming Telnet
    connections and spawns a new thread to handle each client. The server
    runs indefinitely until the program is terminated.

    Note: We bind to port 2323 internally (non-privileged) and Docker maps
    this to port 23 externally via the docker-compose configuration.

    Args:
        local_ip: This sensor's public IP address (for attack reporting)
        max_clients: Maximum concurrent active client connections permitted
    """
    # Create TCP socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to all interfaces on the internal non-privileged port
    server.bind(("0.0.0.0", TELNET_INTERNAL_PORT))  # nosec B104
    server.listen(TELNET_LISTEN_BACKLOG)

    semaphore = threading.BoundedSemaphore(max_clients)

    logging.info(f"[+] Telnet server listening on internal port {TELNET_INTERNAL_PORT}")
    logging.info(f"[+] Attack submissions will report destination IP: {local_ip}")
    logging.info(f"[+] Max concurrent client connections: {max_clients}")

    # Main accept loop with timeout to allow checking shutdown_event
    server.settimeout(1.0)

    while not shutdown_event.is_set():
        try:
            client_socket, addr = server.accept()
        except TimeoutError:
            continue
        except OSError:
            # Socket closed during shutdown
            break
        except Exception as e:
            logging.error(f"[!] Error accepting connection: {e}")
            continue

        logging.debug(f"[+] Connection from {addr[0]}:{addr[1]}")

        # Non-blocking acquisition to protect against DoS / connection floods
        if not semaphore.acquire(blocking=False):
            logging.warning(
                f"[!] Connection limit ({max_clients}) reached. Rejecting connection from {addr[0]}:{addr[1]}"
            )
            try:
                client_socket.sendall(b"Server busy. Connection closed.\r\n")
            except Exception:
                pass
            try:
                client_socket.close()
            except Exception:
                pass
            continue

        # Spawn a new daemon thread to handle this client
        threading.Thread(target=handle_client, args=(client_socket, local_ip, semaphore), daemon=True).start()

    logging.info("[+] Shutting down server socket...")
    try:
        server.close()
    except Exception:
        pass


def handle_shutdown_signal(signum, _frame) -> None:
    """Handle termination signals (SIGTERM, SIGINT) gracefully."""
    sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
    logging.info(f"[+] Received shutdown signal {sig_name}. Initiating graceful shutdown...")
    shutdown_event.set()


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    # Register graceful signal handlers
    signal.signal(signal.SIGINT, handle_shutdown_signal)
    signal.signal(signal.SIGTERM, handle_shutdown_signal)

    logging.info("=" * 60)
    logging.info("[+] Starting NetWatch Telnet AttackPod")
    logging.info("=" * 60)

    # Validate essential environment configurations
    validate_configuration()

    # Display test mode warning prominently
    if _check_if_in_test_mode():
        logging.info("")
        logging.info("################################")
        logging.info("### !!! TEST MODE ACTIVE !!! ###")
        logging.info("################################")
        logging.info("### Attacks will be submitted ##")
        logging.info("### but NOT SAVED by backend  ##")
        logging.info("################################")
        logging.info("")

    # Determine this sensor's public IP address
    # Use explicit configuration if provided, otherwise auto-detect
    ATTACKPOD_LOCAL_IP = get_env("ATTACK_POD_IP", "") or get_local_ip()
    logging.info(f"[+] Sensor destination IP: {ATTACKPOD_LOCAL_IP}")

    # Log configuration for debugging
    logging.info(f"[+] Collector URL: {get_env('NETWATCH_COLLECTOR_URL', DEFAULT_COLLECTOR_URL)}")
    logging.info(f"[+] Sensor UUID: {get_env('SENSOR_UUID', '(not set)')}")
    logging.info(f"[+] TLP Level: {get_env('SENSOR_TLP', 'CLEAR')}")

    # Start the background worker thread for attack forwarding
    worker_thread = threading.Thread(target=attack_forward_worker, daemon=True)
    worker_thread.start()

    # Start the main Telnet server (runs in main thread until shutdown_event)
    start_telnet_server(ATTACKPOD_LOCAL_IP)

    # Wait for attack queue to drain before full process termination
    logging.info("[+] Flushing remaining queued attacks...")
    worker_thread.join(timeout=5.0)
    logging.info("[+] NetWatch Telnet AttackPod stopped cleanly.")
