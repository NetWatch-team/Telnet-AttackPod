import logging
import requests
import os
from datetime import datetime
import threading
import time
import socket
import queue
import json

attack_queue = queue.Queue()
logging.basicConfig(
    encoding="utf-8",
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)

def get_env(key, fallback):
    env = os.getenv(key, default=fallback)
    return env

def _check_if_in_test_mode():
    test = get_env("NETWATCH_TEST_MODE", "false")
    logging.info("Test:" + test)
    if get_env("NETWATCH_TEST_MODE", "false") != "false":
        return True
    return False

def get_local_ip():
    url = f"{get_env('NETWATCH_COLLECTOR_URL', 'https://api.netwatch.team')}/check_ip"
    for attempt in range(50):
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                local_ip = response.json().get("ip")
                logging.info(f"Got the following local IP: {local_ip}")
                return local_ip
            logging.error(f"[!] Got a non 200 status code from the netwatch backend: {response.status_code}, message: {response.text}")
        except requests.RequestException as e:
            logging.error(f"[!] Got a request exception while trying to get the local IP: {e}")
        except Exception as e:
            logging.error(f"[!] Got an exception while trying to get the local IP: {e}")
        time.sleep(10)
    logging.error("[!] The system was unable to get the local IP. Sensor can not work without local IP => Exit with code 1")
    exit(1)

def submit_attack(ip, user, password, evidence, ATTACKPOD_LOCAL_IP, source_port):
    json_dict = {"timestamp": datetime.now().isoformat(),
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
    attack_queue.put(json_dict)

def attack_forward_worker(attack_queue):
    while True:
        json_dict = attack_queue.get()
        url = f"{get_env('NETWATCH_COLLECTOR_URL', '')}/v2/add_attack/telnet_bruteforce"
        headers = {"Authorization": get_env("NETWATCH_COLLECTOR_AUTHORIZATION", "")}
        try:
            response = requests.post(url, json=json_dict, headers=headers, timeout=5)
            if response.status_code == 200:
                if _check_if_in_test_mode():
                    logging.info(f"Reported the following JSON to the NetWatch collector IN TEST MODE ATTACK WILL NOT BE SAVED: {json.dumps(json_dict)}")
                else:
                    logging.info(f"Reported the following JSON to the NetWatch collector: {json.dumps(json_dict)}")
            else:
                logging.error(f"Failed to report attack: {response.status_code}, {response.text}")
        except requests.RequestException as e:
            logging.error(f"Error while forwarding attack data: {e}")

def handle_client(client_socket, ATTACKPOD_LOCAL_IP):
    try:
        client_socket.sendall(b"Username: ")
        username = client_socket.recv(1024).decode().strip()
        client_socket.sendall(b"Password: ")
        password = client_socket.recv(1024).decode().strip()

        if username == "" and password == "":
            logging.info("Empty username & password skipping")
            return

        remote_ip = client_socket.getpeername()[0]

        evidence = f"Login attempt by username '{username}' from ip '{remote_ip}'"
        submit_attack(remote_ip, username, password, evidence, ATTACKPOD_LOCAL_IP, )
    except Exception as e:
        logging.error(f"Error handling client connection: {e}")
    finally:
        client_socket.close()

def start_telnet_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 23))
    server.listen(5)
    logging.info("[+] Telnet server started on port 23")

    while True:
        client_socket, addr = server.accept()
        logging.debug(f"Accepted connection from {addr}")
        threading.Thread(target=handle_client, args=(client_socket, ATTACKPOD_LOCAL_IP)).start()

if __name__ == '__main__':
    logging.info("[+] Starting NetWatch Attackpod")

    if _check_if_in_test_mode():
        logging.info("################################")
        logging.info("################################")
        logging.info("###   !Sensor in test mode!   ##")
        logging.info("### Attacks will be submitted ##")
        logging.info("###       but NOT SAVED       ##")
        logging.info("################################")
        logging.info("################################")

    logging.info("[+] Getting local ip")
    if os.getenv("ATTACK_POD_IP") is not None:
        ATTACKPOD_LOCAL_IP = get_env("ATTACK_POD_IP", "")
    else:
        ATTACKPOD_LOCAL_IP = get_local_ip()

    logging.info("[+] Got the local ip of {} for the AttackPod".format(ATTACKPOD_LOCAL_IP))
    logging.info("[+] Starting attack forward worker")
    attack_submit_worker_thread = threading.Thread(target=attack_forward_worker, args=(attack_queue,))
    attack_submit_worker_thread.start()

    logging.info("[+] Starting Telnet server")
    telnet_server_thread = threading.Thread(target=start_telnet_server)
    telnet_server_thread.start()