#!/usr/bin/env python3
"""
Port Scanner Results Parser
This module helps parse port scanner JSON output and convert it to a format
usable by the vulnerability manager.
"""

import json
import sys
import os

def parse_port_scan_json(json_file):
    """
    Parse JSON output from port scanner into the format expected by vulnerability manager.
    
    Args:
        json_file (str): Path to the JSON file containing port scan results
        
    Returns:
        dict: IP addresses mapped to list of (port, service) tuples
    """
    print(f"[*] Parsing port scan results from: {json_file}")
    
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        formatted_results = {}
        
        # Handle different possible JSON structures
        
        # Structure 1: {"metadata": {...}, "scan_results": {"ip": [{"port": 80, "service": "http"}, ...], ...}
        if isinstance(data, dict) and "scan_results" in data:
            print("[*] Detected enhanced port scanner JSON format")
            for ip, ports_data in data["scan_results"].items():
                formatted_results[ip] = [(p["port"], p["service"]) for p in ports_data]
        
        # Structure 2: {"ip": [{"port": 80, "service": "http"}, ...], ...}
        elif isinstance(data, dict) and all(isinstance(data.get(ip), list) for ip in data.keys()):
            print("[*] Detected direct scan results format")
            for ip, ports_data in data.items():
                if all(isinstance(p, dict) and "port" in p for p in ports_data):
                    formatted_results[ip] = [(p["port"], p.get("service", "unknown")) for p in ports_data]
                else:
                    # Might be already formatted as tuples but serialized as lists
                    formatted_results[ip] = [(p[0], p[1]) for p in ports_data]
        
        # Structure 3: {"ip": {"attacks": {...}, "open_ports": [(80, "http"), ...], ...}, ...}
        elif isinstance(data, dict) and all(isinstance(data.get(ip), dict) and "open_ports" in data.get(ip, {}) for ip in data.keys()):
            print("[*] Detected vulnerability manager format")
            for ip, ip_data in data.items():
                formatted_results[ip] = ip_data["open_ports"]
        
        # Structure 4: {"ip": {"80": {...}, "443": {...}, ...}, ...}
        elif isinstance(data, dict) and all(isinstance(data.get(ip), dict) and all(port.isdigit() for port in data.get(ip, {})) for ip in data.keys()):
            print("[*] Detected attack results format")
            for ip, ports in data.items():
                formatted_results[ip] = [(int(port), "unknown") for port in ports.keys()]
                
        # If we couldn't parse it in a recognized format
        if not formatted_results:
            print("[!] Warning: Could not determine JSON format. Attempting direct use.")
            formatted_results = data
            
        print(f"[+] Successfully parsed data for {len(formatted_results)} hosts")
        
        # Count total open ports
        total_ports = sum(len(ports) for ports in formatted_results.values())
        print(f"[+] Found a total of {total_ports} open ports")
        
        return formatted_results
        
    except json.JSONDecodeError:
        print(f"[!] Error: {json_file} is not a valid JSON file")
        return None
    except FileNotFoundError:
        print(f"[!] Error: File {json_file} not found")
        return None
    except Exception as e:
        print(f"[!] Error parsing JSON: {str(e)}")
        return None

def save_parsed_results(parsed_data, output_file=None):
    """
    Save the parsed results to a JSON file in the format expected by vulnerability manager.
    
    Args:
        parsed_data (dict): The parsed results
        output_file (str): Output file path (optional)
        
    Returns:
        str: Path to the saved file
    """
    if output_file is None:
        # Generate default name based on input
        base_dir = os.path.dirname(os.path.abspath(__file__))
        output_file = os.path.join(base_dir, "parsed_scan_results.json")
    
    try:
        # Convert to vulnerability manager expected format
        formatted_data = {}
        for ip, ports in parsed_data.items():
            formatted_data[ip] = {
                "open_ports": ports,
                "vulnerabilities": [],
                "attacks": []
            }
        
        with open(output_file, 'w') as f:
            json.dump(formatted_data, f, indent=2)
            
        print(f"[+] Saved parsed results to: {output_file}")
        return output_file
    
    except Exception as e:
        print(f"[!] Error saving parsed results: {str(e)}")
        return None

def main():
    """
    Main function for standalone execution.
    """
    if len(sys.argv) < 2:
        print("Usage: python parse_scanner_results.py scan_results.json [output.json]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    parsed_data = parse_port_scan_json(input_file)
    if parsed_data:
        save_parsed_results(parsed_data, output_file)

if __name__ == "__main__":
    main()