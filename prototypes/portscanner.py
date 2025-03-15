import re
import socket
import json
from concurrent.futures import ThreadPoolExecutor

# Regular expression for stricter IPv4 validation
def is_valid_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True

# Regular expression to match port range
port_range_pattern = re.compile(r"(\d+)-(\d+)")

def scan_port(ip, port, results):
    """Attempts to connect to the specified port and stores the result."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            if s.connect_ex((ip, port)) == 0:
                results.append(port)
        except Exception as e:
            print(f"[-] Error scanning port {port}: {e}")

# Get user input for IP address
while True:
    ip_address = input("\nPlease enter the IP address you want to scan: ")
    if is_valid_ip(ip_address):
        print(f"{ip_address} is a valid IP address.")
        break
    else:
        print("Invalid IP address. Try again.")

# Get user input for port range
while True:
    port_range = input("Enter port range (e.g., 20-80): ")
    port_range_valid = port_range_pattern.match(port_range.replace(" ", ""))
    if port_range_valid:
        port_min, port_max = map(int, port_range_valid.groups())
        if 0 <= port_min <= 65535 and 0 <= port_max <= 65535 and port_min <= port_max:
            break
        else:
            print("Invalid port numbers. Ensure ports are between 0-65535.")
    else:
        print("Invalid port range format. Try again.")

print(f"Scanning {ip_address} from port {port_min} to {port_max}...")

# Store results
open_ports = []

# Use ThreadPoolExecutor for efficient threading
with ThreadPoolExecutor(max_workers=50) as executor:
    for port in range(port_min, port_max + 1):
        executor.submit(scan_port, ip_address, port, open_ports)

# Save results to a JSON file
scan_results = {"ip_address": ip_address, "open_ports": open_ports}
with open("scan_results.json", "w") as json_file:
    json.dump(scan_results, json_file, indent=4)

print("Scan complete! Results saved to scan_results.json.")
