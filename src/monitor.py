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
from datetime import datetime
from typing import Optional, Tuple
import threading
import time
import socket
import queue
import json

# ============================================================================
# CONFIGURATION CONSTANTS
# ============================================================================

# NetWatch Collector Configuration
DEFAULT_COLLECTOR_URL = "https://api.netwatch.team"
COLLECTOR_REQUEST_TIMEOUT = int(get_env("COLLECTOR_REQUEST_TIMEOUT", "10"))  # seconds for API requests
CHECK_IP_TIMEOUT = int(get_env("CHECK_IP_TIMEOUT", "5"))  # seconds for IP check requests

# IP Detection Configuration
MAX_IP_RETRY_ATTEMPTS = int(get_env("MAX_IP_RETRY_ATTEMPTS", "50"))  # max attempts to get local IP
IP_RETRY_DELAY_SECONDS = int(get_env("IP_RETRY_DELAY_SECONDS", "10"))  # delay between IP detection retries

# Telnet Server Configuration
TELNET_INTERNAL_PORT = get_env("TELNET_INTERNAL_PORT", "2323")  # non-privileged port inside Docker
TELNET_LISTEN_BACKLOG = int(get_env("TELNET_LISTEN_BACKLOG", "100"))  # max queued connections
CLIENT_TIMEOUT_SECONDS = int(get_env("CLIENT_TIMEOUT_SECONDS", "30"))  # timeout for client connections

# Telnet Protocol Constants
TELNET_IAC = int(get_env("TELNET_IAC", "255"))  # Interpret As Command byte
TELNET_COMMAND_LENGTH = int(get_env("TELNET_COMMAND_LENGTH", "3"))  # IAC commands are typically 3 bytes

# Input Processing Configuration
MAX_INPUT_RETRIES = int(get_env("MAX_INPUT_RETRIES", "30"))  # max attempts to read username/password
INPUT_RETRY_DELAY = float(get_env("INPUT_RETRY_DELAY", "0.1"))  # delay between empty input retries (seconds)
SOCKET_RECV_BUFFER = int(get_env("SOCKET_RECV_BUFFER", "1024"))  # bytes to read at once

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


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is private/non-routable per RFC 1918 and related standards.
    
    This includes:
    - RFC 1918 Private Networks: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    - Loopback Addresses: 127.0.0.0/8
    - Link-Local Addresses: 169.254.0.0/16
    
    Args:
        ip: IP address string to check
        
    Returns:
        True if IP is private/non-routable, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        logging.warning(f"Invalid IP address format: {ip}")
        return False


def get_local_ip() -> str:
    """
    Detect the public IP address of this sensor by querying the NetWatch API.
    
    This function retries multiple times with delays to handle transient
    network issues during startup. If the IP cannot be determined after
    all retries, the program exits.
    
    Returns:
        Public IP address as a string
        
    Raises:
        SystemExit: If IP cannot be detected after max retries
    """
    url = f"{get_env('NETWATCH_COLLECTOR_URL', DEFAULT_COLLECTOR_URL)}/check_ip"
    
    for attempt in range(MAX_IP_RETRY_ATTEMPTS):
        try:
            response = requests.get(url, timeout=CHECK_IP_TIMEOUT)
            if response.status_code == 200:
                local_ip = response.json().get("ip")
                logging.info(f"[+] Detected public IP: {local_ip}")
                return local_ip
            else:
                logging.warning(
                    f"[!] Attempt {attempt + 1}/{MAX_IP_RETRY_ATTEMPTS}: "
                    f"API returned status {response.status_code}"
                )
        except requests.exceptions.RequestException as e:
            logging.error(
                f"[!] Attempt {attempt + 1}/{MAX_IP_RETRY_ATTEMPTS}: "
                f"Error getting local IP: {e}"
            )
        
        # Don't sleep after the last failed attempt
        if attempt < MAX_IP_RETRY_ATTEMPTS - 1:
            time.sleep(IP_RETRY_DELAY_SECONDS)
    
    logging.error("[!] Unable to get local IP after all retries. Exiting.")
    exit(1)


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
    session.headers.update({
        "Authorization": get_env("NETWATCH_COLLECTOR_AUTHORIZATION", "")
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

def telnet_read_filtered_input(client_socket: socket.socket) -> str:
    """
    Read from a Telnet socket and filter out IAC (Interpret As Command) sequences.
    
    Telnet uses in-band signaling where command bytes (starting with 0xFF)
    are mixed with user data. This function strips out the IAC command
    sequences and returns only the actual text entered by the user.
    
    IAC commands are typically 3 bytes: [0xFF] [COMMAND] [OPTION]
    
    Args:
        client_socket: Connected client socket
        
    Returns:
        Clean text input from user, or empty string on error/no data
    """
    try:
        data = client_socket.recv(SOCKET_RECV_BUFFER)
        if not data:
            return ""

        # Filter out Telnet IAC (0xFF) command sequences
        clean_data = bytearray()
        i = 0
        while i < len(data):
            if data[i] == TELNET_IAC:
                # Skip this IAC command (typically 3 bytes)
                i += TELNET_COMMAND_LENGTH
            else:
                # Regular user data - keep it
                clean_data.append(data[i])
                i += 1

        # Decode to UTF-8, ignoring invalid sequences
        return clean_data.decode('utf-8', errors='ignore').strip()
        
    except socket.timeout:
        return ""
    except Exception as e:
        logging.debug(f"Error reading from socket: {e}")
        return ""


def handle_client(client_socket: socket.socket, ATTACKPOD_LOCAL_IP: str) -> None:
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


# ============================================================================
# SERVER MAIN LOOP
# ============================================================================

def start_telnet_server(local_ip: str) -> None:
    """
    Start the main Telnet server loop.
    
    This function creates a socket server that listens for incoming Telnet
    connections and spawns a new thread to handle each client. The server
    runs indefinitely until the program is terminated.
    
    Note: We bind to port 2323 internally (non-privileged) and Docker maps
    this to port 23 externally via the docker-compose configuration.
    
    Args:
        local_ip: This sensor's public IP address (for attack reporting)
    """
    # Create TCP socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Bind to all interfaces on the internal non-privileged port
    server.bind(('0.0.0.0', TELNET_INTERNAL_PORT))
    server.listen(TELNET_LISTEN_BACKLOG)
    
    logging.info(f"[+] Telnet server listening on internal port {TELNET_INTERNAL_PORT}")
    logging.info(f"[+] Attack submissions will report destination IP: {local_ip}")

    # Main accept loop
    while True:
        try:
            client_socket, addr = server.accept()
            logging.debug(f"[+] Connection from {addr[0]}:{addr[1]}")
            
            # Spawn a new daemon thread to handle this client
            # Daemon threads automatically terminate when main program exits
            threading.Thread(
                target=handle_client, 
                args=(client_socket, local_ip), 
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