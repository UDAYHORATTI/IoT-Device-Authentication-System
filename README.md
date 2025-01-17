# IoT-Device-Authentication-System
This script manages a list of authorized IoT devices by storing their MAC addresses, IP addresses, and authentication tokens. It monitors the network for any devices trying to communicate, checks if they are authorized, and only allows legitimate devices to send or receive data.
import scapy.all as scapy
import time
import logging
from collections import defaultdict

# Configuration
NETWORK_INTERFACE = "eth0"  # Network interface for monitoring (use 'wlan0' for WiFi)
LOG_FILE = "iot_authentication.log"  # Log file to store IoT device connection events
AUTHORIZED_DEVICES = {
    '192.168.1.101': {'mac': '00:14:22:01:23:45', 'token': 'ABC123'},  # Example authorized device
    '192.168.1.102': {'mac': '00:14:22:67:89:AB', 'token': 'DEF456'},  # Another authorized device
}
CHECK_INTERVAL = 60  # Time interval to check network usage (in seconds)

# Setting up logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to authenticate IoT device based on its IP, MAC, and token
def authenticate_device(ip, mac, token):
    if ip in AUTHORIZED_DEVICES:
        authorized_mac = AUTHORIZED_DEVICES[ip]['mac']
        authorized_token = AUTHORIZED_DEVICES[ip]['token']
        if mac == authorized_mac and token == authorized_token:
            logging.info(f"Device {ip} with MAC {mac} and token {token} authenticated successfully.")
            return True
        else:
            logging.warning(f"Device {ip} with MAC {mac} and token {token} failed authentication.")
            return False
    else:
        logging.warning(f"Device {ip} is not authorized to connect to the network.")
        return False

# Function to handle incoming packets and authenticate devices
def packet_handler(packet):
    try:
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dest_ip = packet[scapy.IP].dst
            src_mac = packet[scapy.Ether].src
            dest_mac = packet[scapy.Ether].dst
            token = packet[scapy.IP].options  # Example of extracting a token from the packet (this would need to be implemented based on protocol)

            # Authenticate source device
            if not authenticate_device(src_ip, src_mac, token):
                print(f"ALERT: Unauthorized device detected with IP {src_ip} and MAC {src_mac}")
                logging.warning(f"Unauthorized device detected: {src_ip} ({src_mac}) attempting to access the network.")

            # Authenticate destination device
            if not authenticate_device(dest_ip, dest_mac, token):
                print(f"ALERT: Unauthorized device detected with IP {dest_ip} and MAC {dest_mac}")
                logging.warning(f"Unauthorized device detected: {dest_ip} ({dest_mac}) attempting to access the network.")

    except Exception as e:
        logging.error(f"Error processing packet: {e}")

# Function to display the authentication status of IoT devices
def display_status():
    print("IoT Device Authentication Status:")
    print("-" * 50)
    for ip in AUTHORIZED_DEVICES:
        print(f"Device IP: {ip} - Authorized: YES")
    print("-" * 50)

# Function to start the packet sniffing and authentication process
def start_sniffing():
    print("Starting IoT device authentication monitoring...")
    scapy.sniff(iface=NETWORK_INTERFACE, prn=packet_handler, store=0)

# Function to periodically display the authentication status
def run_monitoring():
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

    while True:
        time.sleep(CHECK_INTERVAL)
        display_status()

# Main execution
if __name__ == "__main__":
    run_monitoring()
