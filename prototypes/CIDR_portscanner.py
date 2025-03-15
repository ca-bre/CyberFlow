import re
import socket
import json
import ipaddress
from concurrent.futures import ThreadPoolExecutor

# Regular expression to match port range
port_range_pattern = re.compile(r"(\d+)-(\d+)")

def scan_port(ip, port, results):
    """Attempts to connect to the specified port and stores the result."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            if s.connect_ex((ip, port)) == 0:
                results.append((ip, port))
        except Exception as e:
            print(f"[-] Error scanning port {port} on {ip}: {e}")

# Get user input for IP range (CIDR notation or single IP)
while True:
    ip_input = input("\nPlease enter the IP address or CIDR range you want to scan: ")
    try:
        ip_network = ipaddress.ip_network(ip_input, strict=False)
        print(f"Scanning {ip_network}...")
        break
    except ValueError:
        print("Invalid IP address or CIDR notation. Try again.")

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

# Store results
open_ports = []

# Use ThreadPoolExecutor for efficient threading
with ThreadPoolExecutor(max_workers=50) as executor:
    for ip in ip_network.hosts():  # Iterate over all possible hosts in the network
        for port in range(port_min, port_max + 1):
            executor.submit(scan_port, str(ip), port, open_ports)

# Save results to a JSON file
scan_results = {"scanned_network": str(ip_network), "open_ports": open_ports}
with open("scan_results.json", "w") as json_file:
    json.dump(scan_results, json_file, indent=4)

print("Scan complete! Results saved to scan_results.json.")
