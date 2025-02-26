import nmap
import re
import threading

# Regular Expression Pattern to recognize IPv4 addresses.
ip_add_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
# Regular Expression Pattern to extract the number of ports you want to scan.
port_range_pattern = re.compile(r"([0-9]+)-([0-9]+)")

# List to store results
scan_results = {}
lock = threading.Lock()  # Lock to prevent race conditions when writing to the list

# Function to scan a single port
def scan_port(ip, port, nm):
    try:
        result = nm.scan(ip, str(port))
        port_status = result['scan'][ip]['tcp'][port]['state']
        with lock:  # Ensure only one thread modifies the list at a time
            scan_results["port"] = port_status
    except:
        with lock:
            scan_results["port"]

# Ask user to input the IP address they want to scan.
while True:
    ip_add_entered = input("\nPlease enter the IP address that you want to scan: ")
    if ip_add_pattern.search(ip_add_entered):
        print(f"{ip_add_entered} is a valid IP address")
        break

# Ask user to input the port range they want to scan.
while True:
    print("Please enter the range of ports you want to scan in format: <int>-<int> (e.g., 60-120)")
    port_range = input("Enter port range: ")
    port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
    if port_range_valid:
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
        break

nm = nmap.PortScanner()
threads = []

# Loop over all the ports in the specified range and create a thread for each scan.
for port in range(port_min, port_max + 1):
    thread = threading.Thread(target=scan_port, args=(ip_add_entered, port, nm))
    threads.append(thread)
    thread.start()

# Wait for all threads to finish
for thread in threads:
    thread.join()

# Print all results at the end
print("\nScan complete. Results:")
numPortsScanned = port_max - port_min
for port in range(1, numPortsScanned):  # Ensures output is always in order
    status = scan_results.get(port, "Not scanned")  # Default to "Not scanned" if missing
    print(f"Port {port}: {status}")
