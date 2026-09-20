"""
NetWatch Telnet AttackPod

AttackPod that captures Telnet brute-force login attempts and reports them to
the NetWatch backend for abuse mitigation and notification.

This sensor listens on port 23 (mapped from internal port 2323) and presents
a fake Telnet login prompt. All credentials and source IPs are captured and
forwarded to the central NetWatch backend for processing.
"""

import ipaddress
import logging
import requests
import os
import random
from datetime import datetime
from typing import Optional, Tuple
import threading
import time
import socket
import queue
import json
import sys

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
TELNET_INTERNAL_PORT = os.getenv("TELNET_INTERNAL_PORT", "2323")  # non-privileged port inside Docker
TELNET_LISTEN_BACKLOG = int(os.getenv("TELNET_LISTEN_BACKLOG", "100"))  # max queued connections
CLIENT_TIMEOUT_SECONDS = int(os.getenv("CLIENT_TIMEOUT_SECONDS", "30"))  # timeout for client connections
MAX_CONCURRENT_CLIENTS = int(os.getenv("MAX_CONCURRENT_CLIENTS", "100"))  # max concurrent client connections

# Telnet Protocol Constants
TELNET_IAC = int(os.getenv("TELNET_IAC", "255"))  # Interpret As Command byte (0xFF)
TELNET_DONT = 254
TELNET_DO = 253
TELNET_WONT = 252
TELNET_WILL = 251
TELNET_SB = 250   # Subnegotiation Begin
TELNET_SE = 240   # Subnegotiation End
TELNET_COMMAND_LENGTH = int(os.getenv("TELNET_COMMAND_LENGTH", "3"))  # Standard option negotiation command length

# Input Processing Configuration
MAX_INPUT_RETRIES = int(os.getenv("MAX_INPUT_RETRIES", "30"))  # max attempts to read username/password
INPUT_RETRY_DELAY = float(os.getenv("INPUT_RETRY_DELAY", "0.1"))  # delay between empty input retries (seconds)
SOCKET_RECV_BUFFER = int(os.getenv("SOCKET_RECV_BUFFER", "1024"))  # bytes to read at once
MAX_INPUT_LENGTH = int(os.getenv("MAX_INPUT_LENGTH", "256"))  # max chars allowed for username/password

# ============================================================================
# GLOBAL STATE
# ============================================================================

# Thread-safe queue for attacks pending submission to NetWatch
attack_queue = queue.Queue()

# Configure logging
logging.basicConfig(
    encoding="utf-8",
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)


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


def _check_if_in_test_mode() -> bool:
    """
    Check if the sensor is running in test mode.
    
    In test mode, attacks are submitted to the backend but marked as test data
    and not processed for abuse notifications.
    
    Returns:
        True if test mode is enabled, False otherwise
    """
    return get_env("NETWATCH_TEST_MODE", "false").lower() == "true"


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
                logging.warning(
                    f"[!] Attempt {attempt + 1}/{max_retries}: "
                    f"API returned status {response.status_code}"
                )
        except requests.exceptions.RequestException as e:
            logging.error(
                f"[!] Attempt {attempt + 1}/{max_retries}: "
                f"Error getting local IP: {e}"
            )
        
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
    source_port: int
) -> None:
    """
    Submit a captured attack to the queue for forwarding to NetWatch backend.
    
    This function filters out attacks from/to private IP addresses to prevent
    false positives and reduce backend processing load. Attacks involving
    RFC 1918 addresses, loopback, or link-local addresses are logged but not
    submitted.
    
    Args:
        ip: Source IP address of the attacker
        user: Username used in login attempt
        password: Password used in login attempt
        evidence: Human-readable description of the attack
        ATTACKPOD_LOCAL_IP: Destination IP (this sensor's public IP)
        source_port: Source port of the attacker's connection
    """
    # Filter out attacks involving private/local IPs
    if is_private_ip(ip) or is_private_ip(ATTACKPOD_LOCAL_IP):
        logging.info(
            f"[FILTERED] Skipping attack from/to private IP - "
            f"Source: {ip}, Destination: {ATTACKPOD_LOCAL_IP}, User: {user}"
        )
        return
    
    # Build attack payload according to NetWatch API specification
    json_dict = {
        "timestamp": datetime.now().isoformat(),
        "uuid": get_env("SENSOR_UUID", ""),
        "tlp": get_env("SENSOR_TLP", "CLEAR"),
        "source": ip,
        "destination": ATTACKPOD_LOCAL_IP,
        "attack_type": "TELNET_BRUTE_FORCE",
        "source_type": "IP",
        "test_mode": _check_if_in_test_mode(),
        "evidence": evidence,
        "metadata": {
            "username": user,
            "password": password,
            "source_port": source_port
        }
    }
    
    # Queue the attack for async submission
    attack_queue.put(json_dict)


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
    session.headers.update({
        "Authorization": get_env("NETWATCH_COLLECTOR_AUTHORIZATION", ""),
        "User-Agent": "NetWatch-Telnet-AttackPod/0.2"
    })
    url = f"{get_env('NETWATCH_COLLECTOR_URL', DEFAULT_COLLECTOR_URL)}/v2/add_attack/telnet_bruteforce"

    logging.info("[+] Attack forwarding worker started")

    while True:
        # Block until an attack is available
        json_dict = attack_queue.get()
        
        try:
            response = session.post(url, json=json_dict, timeout=COLLECTOR_REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                # Success - format log message based on test mode
                status = "TEST MODE (NOT SAVED)" if _check_if_in_test_mode() else "SUCCESS"
                logging.info(
                    f"[{status}] Reported: {json_dict['source']} -> "
                    f"{json_dict['metadata']['username']}"
                )
            else:
                # Non-200 status code from API
                logging.error(
                    f"[!] API Error: {response.status_code} - {response.text[:200]}"
                )
                
        except requests.exceptions.Timeout:
            logging.error(
                f"[!] Timeout forwarding attack from {json_dict.get('source', 'unknown')}"
            )
        except requests.exceptions.RequestException as e:
            logging.error(
                f"[!] Network error forwarding attack from "
                f"{json_dict.get('source', 'unknown')}: {e}"
            )
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

def filter_telnet_iac(data: bytes) -> Tuple[bytearray, bytes]:
    """
    Filter out Telnet IAC (Interpret As Command) sequences per RFC 854.
    
    Handles:
    - Escaped IAC (0xFF 0xFF) -> literal 0xFF
    - Option negotiation (WILL, WONT, DO, DONT) -> 3 bytes
    - Subnegotiation (SB ... SE) -> variable length
    - Other 2-byte commands (NOP, DM, etc.) -> 2 bytes
    
    Args:
        data: Raw byte stream received from socket
        
    Returns:
        Tuple of (clean_payload_bytes, remaining_incomplete_iac_bytes)
    """
    clean_data = bytearray()
    i = 0
    n = len(data)
    
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
    max_length: int = MAX_INPUT_LENGTH
) -> str:
    """
    Read a complete line from a Telnet socket, filtering out IAC command sequences
    and respecting maximum input length caps.
    
    Accumulates data until a newline (\\r or \\n) delimiter is encountered or
    until max retries/timeouts are reached.
    
    Args:
        client_socket: Connected client socket
        max_length: Maximum allowed characters to prevent memory exhaustion
        
    Returns:
        Clean text input from user, or empty string on error/no data
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
            clean_chunk, iac_buffer = filter_telnet_iac(iac_buffer + raw_chunk)
            
            if clean_chunk:
                accumulated_clean.extend(clean_chunk)
                
                # Check for line completion (\r or \n)
                if b"\n" in clean_chunk or b"\r" in clean_chunk:
                    break
            else:
                # Only IAC commands received in this chunk
                retries += 1
                time.sleep(INPUT_RETRY_DELAY)
                
        except socket.timeout:
            break
        except Exception as e:
            logging.debug(f"Error reading from socket: {e}")
            break
            
    # Decode to UTF-8, strip whitespace and line endings, enforce max length cap
    decoded = accumulated_clean.decode("utf-8", errors="ignore").strip()
    return decoded[:max_length]


def handle_client(
    client_socket: socket.socket, 
    ATTACKPOD_LOCAL_IP: str, 
    semaphore: Optional[threading.BoundedSemaphore] = None
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
            username = telnet_read_filtered_input(client_socket)
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
            password = telnet_read_filtered_input(client_socket)
            if not password:
                retry_count += 1
                time.sleep(INPUT_RETRY_DELAY)
        
        # If no password, still log what we got
        if not password:
            logging.debug("No password received after max retries")
            return

        # Step 4: Log and submit the attack
        remote_ip, remote_port = client_socket.getpeername()
        logging.info(f"[CAPTURE] {username} / {password} from {remote_ip}:{remote_port}")

        evidence = f"Telnet login attempt by username '{username}' from ip '{remote_ip}'"
        submit_attack(remote_ip, username, password, evidence, ATTACKPOD_LOCAL_IP, remote_port)

        # Step 5: Mimic real server behavior - delay and reject
        time.sleep(random.uniform(0.2, 2.3))  # Realistic processing delay
        client_socket.sendall(b"\r\nLogin incorrect\r\n\r\n")

    except socket.timeout:
        logging.debug("Client connection timed out")
    except ConnectionResetError:
        logging.debug("Client connection reset")
    except Exception as e:
        logging.debug(f"Client handler error: {e}")
    finally:
        # Always close the socket
        try:
            client_socket.close()
        except:
            pass
        if semaphore:
            semaphore.release()


# ============================================================================
# SERVER MAIN LOOP
# ============================================================================

def start_telnet_server(
    local_ip: str, 
    max_clients: int = MAX_CONCURRENT_CLIENTS
) -> None:
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
    server.bind(('0.0.0.0', TELNET_INTERNAL_PORT))
    server.listen(TELNET_LISTEN_BACKLOG)
    
    semaphore = threading.BoundedSemaphore(max_clients)

    logging.info(f"[+] Telnet server listening on internal port {TELNET_INTERNAL_PORT}")
    logging.info(f"[+] Attack submissions will report destination IP: {local_ip}")
    logging.info(f"[+] Max concurrent client connections: {max_clients}")

    # Main accept loop
    while True:
        try:
            client_socket, addr = server.accept()
            logging.debug(f"[+] Connection from {addr[0]}:{addr[1]}")
            
            # Non-blocking acquisition to protect against DoS / connection floods
            if not semaphore.acquire(blocking=False):
                logging.warning(
                    f"[!] Connection limit ({max_clients}) reached. "
                    f"Rejecting connection from {addr[0]}:{addr[1]}"
                )
                try:
                    client_socket.sendall(b"Server busy. Connection closed.\r\n")
                except:
                    pass
                try:
                    client_socket.close()
                except:
                    pass
                continue

            # Spawn a new daemon thread to handle this client
            # Daemon threads automatically terminate when main program exits
            threading.Thread(
                target=handle_client, 
                args=(client_socket, local_ip, semaphore), 
                daemon=True
            ).start()
            
        except Exception as e:
            logging.error(f"[!] Error accepting connection: {e}")
            # Continue listening despite errors


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    logging.info("=" * 60)
    logging.info("[+] Starting NetWatch Telnet AttackPod")
    logging.info("=" * 60)

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
    ATTACKPOD_LOCAL_IP = get_env("ATTACK_POD_IP", None) or get_local_ip()
    logging.info(f"[+] Sensor destination IP: {ATTACKPOD_LOCAL_IP}")
    
    # Log configuration for debugging
    logging.info(f"[+] Collector URL: {get_env('NETWATCH_COLLECTOR_URL', DEFAULT_COLLECTOR_URL)}")
    logging.info(f"[+] Sensor UUID: {get_env('SENSOR_UUID', '(not set)')}")
    logging.info(f"[+] TLP Level: {get_env('SENSOR_TLP', 'CLEAR')}")

    # Start the background worker thread for attack forwarding
    threading.Thread(target=attack_forward_worker, daemon=True).start()

    # Start the main Telnet server (runs in main thread)
    start_telnet_server(ATTACKPOD_LOCAL_IP)