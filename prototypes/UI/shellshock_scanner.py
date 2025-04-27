# NOT TESTED
#!/usr/bin/env python3
"""
Shellshock Vulnerability Scanner Module for CyberFlow UI
Takes port scanner results as input and checks for the Shellshock vulnerability.
"""

import sys
import json
from datetime import datetime

# Parse JSON input from Node.js
data_str = sys.argv[1] if len(sys.argv) > 1 else "{}"
data = json.loads(data_str)

# Extract scan results from input
scan_results = data.get("scan_results", {})

class ShellshockScanner:
    def __init__(self, scan_results):
        self.scan_results = scan_results
        self.results = {}
        
    def process_scan_results(self):
        # Shellshock typically affects CGI scripts on web servers
        # Look for web servers on ports 80, 443, 8080, etc.
        for ip, ports_data in self.scan_results.items():
            self.results[ip] = {
                "potentially_vulnerable": False,
                "ports": [],
                "services": []
            }
            
            # Check if we have a list of port data
            if isinstance(ports_data, list):
                for item in ports_data:
                    # Handle dictionary format
                    if isinstance(item, dict):
                        port = item.get("port")
                        service = item.get("service", "").lower()
                        
                        # Check for web services
                        if (service in ["http", "https"] or 
                            port in [80, 443, 8080, 8443, 8000, 8008]):
                            self.results[ip]["potentially_vulnerable"] = True
                            self.results[ip]["ports"].append(port)
                            self.results[ip]["services"].append(service or "unknown")
                    
                    # Handle tuple/list format
                    elif isinstance(item, (list, tuple)) and len(item) >= 2:
                        port = item[0]
                        service = item[1].lower() if isinstance(item[1], str) else ""
                        
                        if (service in ["http", "https"] or 
                            port in [80, 443, 8080, 8443, 8000, 8008]):
                            self.results[ip]["potentially_vulnerable"] = True
                            self.results[ip]["ports"].append(port)
                            self.results[ip]["services"].append(service or "unknown")
            
            # Calculate vulnerability likelihood
            if self.results[ip]["potentially_vulnerable"]:
                self.results[ip]["vulnerability_likelihood"] = "Medium"
                self.results[ip]["details"] = {
                    "description": "The host is running web services that could potentially be vulnerable to Shellshock if using CGI scripts with Bash.",
                    "affected_ports": self.results[ip]["ports"],
                    "recommendation": "Check if the server uses CGI scripts and ensure Bash is patched (versions after 4.3)."
                }
        
        return self.results

# Main execution
try:
    if not scan_results:
        result = {
            "status": "error",
            "message": "No scan results provided or invalid format",
            "timestamp": datetime.now().isoformat()
        }
    else:
        scanner = ShellshockScanner(scan_results)
        vulnerability_results = scanner.process_scan_results()
        
        # Count potentially vulnerable hosts
        vulnerable_count = sum(1 for ip, data in vulnerability_results.items() 
                              if data.get("potentially_vulnerable", False))
        
        result = {
            "status": "success",
            "summary": {
                "total_hosts": len(vulnerability_results),
                "potentially_vulnerable_hosts": vulnerable_count,
                "scan_type": "Shellshock Vulnerability Scan"
            },
            "details": vulnerability_results,
            "timestamp": datetime.now().isoformat()
        }

    # Output results as JSON
    print(json.dumps({"message": result}))

except Exception as e:
    error_output = {
        "status": "error",
        "message": f"Error processing Shellshock scan: {str(e)}",
        "timestamp": datetime.now().isoformat()
    }
    print(json.dumps({"message": error_output}))