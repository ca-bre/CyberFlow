#!/usr/bin/env python3
"""
Vsftpd Vulnerability Scanner Module for CyberFlow UI
Takes port scanner results as input and checks for vsftpd backdoor vulnerability.
"""

import sys
import json
from datetime import datetime

# Parse JSON input from Node.js
data_str = sys.argv[1] if len(sys.argv) > 1 else "{}"
data = json.loads(data_str)

# Extract scan results from input
scan_results = data.get("scan_results", {})

class VsftpdScanner:
    def __init__(self, scan_results):
        self.scan_results = scan_results
        self.results = {}

    def process_scan_results(self):
        for ip, ports_data in self.scan_results.items():
            self.results[ip] = {"vsftpd_vulnerable": "No"}
            if isinstance(ports_data, list):
                for item in ports_data:
                    if isinstance(item, dict) and item.get("port") == 21 and item.get("service") == "ftp":
                        self.results[ip]["vsftpd_vulnerable"] = "Yes"
                        break
                    elif isinstance(item, (list, tuple)) and item[0] == 21 and item[1] == "ftp":
                        self.results[ip]["vsftpd_vulnerable"] = "Yes"
                        break
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
        scanner = VsftpdScanner(scan_results)
        vulnerability_results = scanner.process_scan_results()

        result = {
            "status": "success",
            "details": vulnerability_results,
            "timestamp": datetime.now().isoformat()
        }

    # Output results as JSON
    print(json.dumps({"message": result}))

except Exception as e:
    error_output = {
        "status": "error",
        "message": f"Error processing vsftpd scan: {str(e)}",
        "timestamp": datetime.now().isoformat()
    }
    print(json.dumps({"message": error_output}))