import re
import socket
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor

# Regular expression for port range
port_range_pattern = re.compile(r"([0-9]+)-([0-9]+)")

# Function to scan a single port
def scan_port(ip, port, open_ports):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)  # Shorter timeout for speed
            if s.connect_ex((ip, port)) == 0:
                print(f"[+] {ip}:{port} is open.")
                open_ports[ip].append(port)
    except Exception:
        pass  # Suppress errors

# Get valid CIDR subnet from user
while True:
    subnet_input = input("\nEnter an IP address or CIDR subnet (e.g., 192.168.1.0/24): ")
    try:
        subnet = ipaddress.ip_network(subnet_input, strict=False)  # Allow single IPs too
        print(f"Scanning subnet: {subnet}")
        break
    except ValueError:
        print("Invalid CIDR notation. Try again.")

# Get valid port range from user
while True:
    port_range = input("Enter port range (e.g., 20-80): ")
    port_range_valid = port_range_pattern.fullmatch(port_range.replace(" ", ""))
    if port_range_valid:
        port_min, port_max = int(port_range_valid.group(1)), int(port_range_valid.group(2))
        break
    else:
        print("Invalid port range. Try again.")

print(f"\nScanning {subnet} from port {port_min} to {port_max}...\n")

# Dictionary to store open ports per IP
open_ports = {str(ip): [] for ip in subnet.hosts()}

# Thread pool for efficiency
with ThreadPoolExecutor(max_workers=100) as executor:
    for ip in subnet.hosts():
        for port in range(port_min, port_max + 1):
            executor.submit(scan_port, str(ip), port, open_ports)

# Display results
print("\nScan complete! Open ports found:")
found_any = False
for ip, ports in open_ports.items():
    if ports:
        found_any = True
        print(f"{ip}: {', '.join(map(str, ports))}")

if not found_any:
    print("No open ports found on any IP.")

