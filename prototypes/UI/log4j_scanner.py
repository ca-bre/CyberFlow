#!/usr/bin/env python3
"""
Log4j Vulnerability Scanner Module for CyberFlow UI
Takes port scanner results as input and checks for potential Log4j vulnerabilities.
"""

import sys
import json
from datetime import datetime

# Parse JSON input from Node.js
data_str = sys.argv[1] if len(sys.argv) > 1 else "{}"
data = json.loads(data_str)

# Extract scan results from input
scan_results = data.get("scan_results", {})

class Log4jScanner:
    def __init__(self, scan_results):
        self.scan_results = scan_results
        self.results = {}
        self.java_ports = [8080, 8443, 9200, 9300, 8000, 8008, 8888, 9000, 9090, 7001, 7002, 8081, 8181, 8983]
        self.java_services = ["http", "https", "tomcat", "weblogic", "elasticsearch", "solr", "jboss", "glassfish", "jenkins", "spring"]
        
    def process_scan_results(self):
        """Process port scanner results to identify potential Log4j vulnerabilities"""
        # Handle the specific format coming from PortScanner
        if isinstance(self.scan_results, str):
            try:
                # Try to parse as JSON if it's a string
                self.scan_results = json.loads(self.scan_results)
            except json.JSONDecodeError as e:
                print(f"Error parsing scan results: {e}")
                # If we can't parse it, create an empty result
                self.scan_results = {}

        # Convert the format if needed (from PortScanner format to expected format)
        converted_results = {}
        for ip, ports_data in self.scan_results.items():
            # Check if the format is a list of lists like [[21, "ftp"], [80, "http"]]
            if isinstance(ports_data, list) and all(isinstance(p, list) for p in ports_data):
                # Convert to the expected format
                converted_results[ip] = [{"port": p[0], "service": p[1]} for p in ports_data]
            else:
                # Keep as is if it's already in the right format
                converted_results[ip] = ports_data

        # Use the converted results
        self.scan_results = converted_results
        
        for ip, ports_data in self.scan_results.items():
            self.results[ip] = {
                "potentially_vulnerable": False,
                "vulnerable_ports": [],
                "services": [],
                "vulnerability_likelihood": "Low",
                "risk_score": 0,
                "cve_id": "CVE-2021-44228",
                "details": {}
            }
            
            # Check if we have a list of port data
            if isinstance(ports_data, list):
                for item in ports_data:
                    # Handle dictionary format
                    if isinstance(item, dict):
                        port = item.get("port")
                        service = item.get("service", "").lower()
                        self._check_port_service(ip, port, service)
                    
                    # Handle tuple/list format
                    elif isinstance(item, (list, tuple)) and len(item) >= 2:
                        port = item[0]
                        service = item[1].lower() if isinstance(item[1], str) else ""
                        self._check_port_service(ip, port, service)
            
            # Calculate vulnerability likelihood and add details
            self._assess_vulnerability(ip)
        
        return self.results
    
    def _check_port_service(self, ip, port, service):
        """Check if a specific port/service combination might indicate Log4j vulnerability"""
        is_java_port = port in self.java_ports
        is_java_service = any(js in service for js in self.java_services)
        
        if is_java_port or is_java_service:
            self.results[ip]["potentially_vulnerable"] = True
            self.results[ip]["vulnerable_ports"].append({
                "port": port,
                "service": service,
                "indicators": {
                    "is_java_port": is_java_port,
                    "is_java_service": is_java_service
                }
            })
            if service and service not in self.results[ip]["services"]:
                self.results[ip]["services"].append(service)
    
    def _assess_vulnerability(self, ip):
        """Assess the likelihood of Log4j vulnerability based on detected ports/services"""
        host_result = self.results[ip]
        
        if not host_result["potentially_vulnerable"]:
            return
        
        # Count matching indicators
        java_service_count = len(host_result["services"])
        java_port_count = len(host_result["vulnerable_ports"])
        
        # Calculate risk score
        risk_score = 0
        if java_service_count > 0:
            risk_score += java_service_count * 15  # Each Java service adds 15 points
        
        for port_data in host_result["vulnerable_ports"]:
            port = port_data["port"]
            service = port_data["service"]
            
            # Known high-risk combinations get more points
            if service in ["elasticsearch", "solr"]:
                risk_score += 25
            elif service in ["tomcat", "weblogic", "jboss"]:
                risk_score += 20
            elif service in ["http", "https"] and port in [8080, 8443, 8000]:
                risk_score += 15
            else:
                risk_score += 10
        
        # Cap at 100
        host_result["risk_score"] = min(risk_score, 100)
        
        # Evaluate vulnerability likelihood
        if host_result["risk_score"] >= 70:
            host_result["vulnerability_likelihood"] = "High"
        elif host_result["risk_score"] >= 40:
            host_result["vulnerability_likelihood"] = "Medium"
        else:
            host_result["vulnerability_likelihood"] = "Low"
        
        # Add detailed information
        host_result["details"] = {
            "description": "Log4Shell (CVE-2021-44228) is a critical vulnerability in Apache Log4j 2 versions below 2.15.0. "
                          "It allows attackers to execute arbitrary code by using JNDI injection via specially crafted log messages.",
            "affected_ports": [p["port"] for p in host_result["vulnerable_ports"]],
            "detected_services": host_result["services"],
            "indicators": [
                "Java-based services detected on typical ports",
                "Web services that commonly use Log4j for logging"
            ],
            "attack_vectors": [
                f"JNDI injection via User-Agent header to port {p['port']}" for p in host_result["vulnerable_ports"] if p["service"] in ["http", "https"]
            ],
            "recommendation": "Update Apache Log4j to version 2.15.0 or later. "
                             "Set system property 'log4j2.formatMsgNoLookups=true' or environment variable 'LOG4J_FORMAT_MSG_NO_LOOKUPS=true' as a mitigation. "
                             "Implement WAF rules to block JNDI lookup patterns."
        }

    def generate_html_report(self, vulnerability_listing, summary):
        """Generate an HTML report for better UI display"""
        
        # Risk level to color mapping
        risk_colors = {
            "High": "#dc3545",
            "Medium": "#fd7e14",
            "Low": "#ffc107"
        }
        
        html = f"""
        <div style="font-family: Arial, sans-serif; max-height: 400px; overflow: auto; padding: 0;">
            <div style="background-color: #f8f9fa; border-left: 4px solid #0d6efd; padding: 15px; margin-bottom: 15px;">
                <h3 style="margin-top: 0; color: #0d6efd; font-size: 18px;">Log4j Vulnerability Scan Summary</h3>
                <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                    <div style="flex: 1;">
                        <div><strong>Total hosts:</strong> {summary['total_hosts']}</div>
                        <div><strong>Vulnerable hosts:</strong> {summary['potentially_vulnerable_hosts']}</div>
                        <div><strong>Scan timestamp:</strong> {summary.get('timestamp', '').split('T')[0]}</div>
                    </div>
                    <div style="flex: 1;">
                        <div><strong>High risk:</strong> {summary['high_risk_hosts']}</div>
                        <div><strong>Medium risk:</strong> {summary['medium_risk_hosts']}</div>
                        <div><strong>Low risk:</strong> {summary['low_risk_hosts']}</div>
                    </div>
                </div>
                <div style="font-size: 13px; background-color: #e9ecef; padding: 8px; border-radius: 4px;">
                    <strong>CVE-2021-44228 (Log4Shell):</strong> Critical vulnerability in Apache Log4j allowing remote code execution via JNDI injection.
                </div>
            </div>
        """
        
        # Generate vulnerable hosts section if any found
        if summary['potentially_vulnerable_hosts'] > 0:
            html += f"""
            <div style="margin-bottom: 15px;">
                <h3 style="margin-top: 0; font-size: 16px; border-bottom: 1px solid #dee2e6; padding-bottom: 8px;">
                    Vulnerable Hosts ({summary['potentially_vulnerable_hosts']})
                </h3>
            """
            
            # Add each vulnerable host
            for host in vulnerability_listing:
                risk_color = risk_colors.get(host['risk_level'], "#6c757d")
                
                html += f"""
                <div style="border: 1px solid #dee2e6; border-radius: 4px; margin-bottom: 10px; overflow: hidden;">
                    <div style="display: flex; justify-content: space-between; align-items: center; background-color: {risk_color}; color: white; padding: 8px 12px;">
                        <div style="font-weight: bold;">{host['ip']}</div>
                        <div style="display: flex; align-items: center;">
                            <div style="background-color: rgba(255,255,255,0.3); border-radius: 4px; padding: 2px 8px; margin-right: 8px;">
                                {host['risk_level']} Risk
                            </div>
                            <div style="background-color: rgba(255,255,255,0.3); border-radius: 4px; padding: 2px 8px;">
                                Score: {host['risk_score']}/100
                            </div>
                        </div>
                    </div>
                    <div style="padding: 10px;">
                        <div style="margin-bottom: 8px;">
                            <div style="font-weight: bold; margin-bottom: 4px;">Vulnerable Ports & Services:</div>
                            <div style="display: flex; flex-wrap: wrap; gap: 5px;">
                """
                
                # Add port badges
                for port in host['vulnerable_ports']:
                    html += f"""
                                <span style="background-color: #e9ecef; border-radius: 4px; padding: 2px 8px; font-size: 13px;">
                                    {port}
                                </span>
                    """
                
                # Add service badges if available
                for service in host.get('services', []):
                    html += f"""
                                <span style="background-color: #cfe2ff; border-radius: 4px; padding: 2px 8px; font-size: 13px;">
                                    {service}
                                </span>
                    """
                
                html += f"""
                            </div>
                        </div>
                """
                
                # Add attack vectors if available
                if host.get('attack_vectors'):
                    html += f"""
                        <div>
                            <div style="font-weight: bold; margin-bottom: 4px;">Potential Attack Vectors:</div>
                            <ul style="margin: 0; padding-left: 20px;">
                    """
                    
                    for vector in host['attack_vectors']:
                        html += f"""
                                <li style="font-size: 13px;">{vector}</li>
                        """
                    
                    html += f"""
                            </ul>
                        </div>
                    """
                
                html += f"""
                    </div>
                </div>
                """
            
            html += "</div>"
        else:
            # No vulnerable hosts found
            html += f"""
            <div style="background-color: #d1e7dd; border-left: 4px solid #198754; padding: 15px; margin-bottom: 15px;">
                <h3 style="margin-top: 0; color: #198754; font-size: 16px;">No Vulnerable Hosts Detected</h3>
                <p style="margin-bottom: 0;">
                    None of the scanned hosts appear to be running services potentially vulnerable to Log4j (CVE-2021-44228).
                </p>
            </div>
            """
        
        # Add remediation advice
        html += f"""
        <div style="background-color: #f8f9fa; border-left: 4px solid #6c757d; padding: 15px;">
            <h3 style="margin-top: 0; color: #6c757d; font-size: 16px;">Remediation Advice</h3>
            <ul style="margin: 0; padding-left: 20px;">
                <li style="margin-bottom: 5px;">Update Apache Log4j to version 2.15.0 or later</li>
                <li style="margin-bottom: 5px;">Set system property 'log4j2.formatMsgNoLookups=true'</li>
                <li style="margin-bottom: 5px;">Implement WAF rules to block JNDI lookup patterns</li>
                <li style="margin-bottom: 0;">Apply vendor-specific patches for affected applications</li>
            </ul>
        </div>
        </div>
        """
        
        return html

# Main execution
try:
    if not scan_results:
        result = {
            "status": "error",
            "message": "No scan results provided or invalid format",
            "timestamp": datetime.now().isoformat()
        }
    else:
        scanner = Log4jScanner(scan_results)
        vulnerability_results = scanner.process_scan_results()
        
        # Filter to just vulnerable hosts for clearer display
        vulnerable_hosts = {ip: data for ip, data in vulnerability_results.items() 
                           if data.get("potentially_vulnerable", False)}
        
        # Count by likelihood
        high_risk = sum(1 for ip, data in vulnerability_results.items() 
                        if data.get("vulnerability_likelihood") == "High")
        medium_risk = sum(1 for ip, data in vulnerability_results.items() 
                         if data.get("vulnerability_likelihood") == "Medium")
        low_risk = sum(1 for ip, data in vulnerability_results.items() 
                      if data.get("vulnerability_likelihood") == "Low" and data.get("potentially_vulnerable"))
        
        # Create vulnerability listing with detailed information
        vulnerability_listing = []
        for ip, data in vulnerable_hosts.items():
            vulnerability_listing.append({
                "ip": ip,
                "risk_level": data["vulnerability_likelihood"],
                "risk_score": data["risk_score"],
                "vulnerable_ports": [p["port"] for p in data["vulnerable_ports"]],
                "services": data["services"],
                "attack_vectors": data["details"]["attack_vectors"] if "attack_vectors" in data["details"] else []
            })
        
        # Sort by risk score (highest first)
        vulnerability_listing.sort(key=lambda x: x["risk_score"], reverse=True)
        
        # Create the summary data
        summary = {
            "total_hosts": len(vulnerability_results),
            "potentially_vulnerable_hosts": len(vulnerable_hosts),
            "high_risk_hosts": high_risk,
            "medium_risk_hosts": medium_risk,
            "low_risk_hosts": low_risk,
            "scan_type": "Log4j Vulnerability Scan (CVE-2021-44228)",
            "timestamp": datetime.now().isoformat()
        }
        
        # Generate HTML report
        html_report = scanner.generate_html_report(vulnerability_listing, summary)
        
        result = {
            "status": "success",
            "summary": summary,
            "vulnerable_hosts": vulnerability_listing,
            "details": vulnerability_results,
            "html_report": html_report,
            "timestamp": datetime.now().isoformat()
        }

    # Output results as JSON
    print(json.dumps({"message": result}))

except Exception as e:
    error_output = {
        "status": "error",
        "message": f"Error processing Log4j scan: {str(e)}",
        "timestamp": datetime.now().isoformat()
    }
    print(json.dumps({"message": error_output}))