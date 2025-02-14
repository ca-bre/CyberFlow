import re
import socket
import threading

# Regular expression to match IPv4 addresses
ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")

# Function to scan a single port
def scan_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)  # Timeout for responsiveness
        if s.connect_ex((ip, port)) == 0:
            print(f"Port {port} is open.")

# Ask user for an IP address
while True:
    ip_address = input("\nPlease enter the IP address you want to scan: ")
    if ip_add_pattern.search(ip_address):
        print(f"{ip_address} is a valid IP address")
        break
    else:
        print("Invalid IP address. Try again.")

# Ask user for a port range
while True:
    port_range = input("Enter port range (e.g., 20-80): ")
    port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
    if port_range_valid:
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
        break
    else:
        print("Invalid port range. Try again.")

print(f"Scanning {ip_address} from port {port_min} to {port_max}...")

# Use threading to scan ports faster
threads = []
for port in range(port_min, port_max + 1):
    thread = threading.Thread(target=scan_port, args=(ip_address, port))
    threads.append(thread)
    thread.start()

# Wait for all threads to finish
for thread in threads:
    thread.join()

print("Scan complete!")
