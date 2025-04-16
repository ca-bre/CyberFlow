from flask import Flask, request, jsonify, send_from_directory
import subprocess
import json
import os
import threading
import time
import re
from pathlib import Path

app = Flask(__name__, static_url_path='')

# Global variables to track job status
scan_status = {"status": "idle", "progress": 0, "results": {}}
vuln_status = {"status": "idle", "progress": 0, "results": {}}
attack_status = {"status": "idle", "progress": 0, "results": {}}

# Output directories
REPORTS_DIR = os.path.join(os.getcwd(), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Serve static files
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('.', path)

# API endpoint for port scanning
@app.route('/api/scan', methods=['POST'])
def run_scan():
    global scan_status
    
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Missing request body"}), 400
            
        target = data.get('target')
        ports = data.get('ports')
        
        if not target:
            return jsonify({"error": "Target IP is required"}), 400
        
        # Validate IP address format
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
            return jsonify({"error": "Invalid IP address format"}), 400
            
        # Validate port specification if provided
        if ports:
            try:
                # Simple validation to check if ports format is valid
                for part in ports.split(','):
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        if start < 1 or end > 65535 or start > end:
                            raise ValueError()
                    else:
                        port = int(part)
                        if port < 1 or port > 65535:
                            raise ValueError()
            except ValueError:
                return jsonify({"error": "Invalid port specification"}), 400
        
        # Reset status
        scan_status = {
            "status": "running", 
            "progress": 0, 
            "target": target,
            "ports": ports,
            "results": {},
            "start_time": time.time()
        }
        
        # Run the scan in a separate thread to avoid blocking
        scan_thread = threading.Thread(
            target=run_port_scan, 
            args=(target, ports)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        # Return immediately with status
        return jsonify({"status": "started", "target": target})
    
    except Exception as e:
        print(f"Error handling scan request: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/api/scan/status', methods=['GET'])
def get_scan_status():
    global scan_status
    return jsonify(scan_status)

# API endpoint for vulnerability assessment
@app.route('/api/assess', methods=['POST'])
def run_assessment():
    global vuln_status
    
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Missing request body"}), 400
            
        scan_results = data.get('scan_results')
        
        if not scan_results:
            return jsonify({"error": "Scan results are required"}), 400
        
        # Validate scan results format
        try:
            for ip, ports in scan_results.items():
                if not isinstance(ip, str):
                    return jsonify({"error": f"Invalid IP address: {ip} (not a string)"}), 400
                if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                    return jsonify({"error": f"Invalid IP address format: {ip}"}), 400
                if not isinstance(ports, list):
                    return jsonify({"error": f"Invalid ports for {ip}: not a list"}), 400
        except Exception as e:
            return jsonify({"error": f"Invalid scan results format: {str(e)}"}), 400
        
        # Save scan results to a file for the vulnerability manager
        timestamp = int(time.time())
        scan_results_file = os.path.join(REPORTS_DIR, f"scan_input_{timestamp}.json")
        with open(scan_results_file, 'w') as f:
            json.dump(scan_results, f)
        
        # Reset status
        vuln_status = {
            "status": "running", 
            "progress": 0, 
            "results": {},
            "start_time": time.time()
        }
        
        # Run vulnerability assessment in a thread
        assessment_thread = threading.Thread(
            target=run_vulnerability_assessment,
            args=(scan_results,)
        )
        assessment_thread.daemon = True
        assessment_thread.start()
        
        return jsonify({"status": "started"})
    
    except Exception as e:
        print(f"Error handling vulnerability assessment request: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/api/assess/status', methods=['GET'])
def get_assessment_status():
    global vuln_status
    return jsonify(vuln_status)

# API endpoint for attack execution
@app.route('/api/attack', methods=['POST'])
def run_attack_manager():
    global attack_status
    
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Missing request body"}), 400
            
        vulnerability_results = data.get('vulnerability_results')
        
        if not vulnerability_results:
            return jsonify({"error": "Vulnerability results are required"}), 400
        
        # Validate vulnerability results format
        try:
            for ip, host_data in vulnerability_results.items():
                if not isinstance(ip, str) or not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                    return jsonify({"error": f"Invalid IP address format: {ip}"}), 400
                if "vulnerabilities" not in host_data:
                    return jsonify({"error": f"Missing vulnerabilities data for host {ip}"}), 400
        except Exception as e:
            return jsonify({"error": f"Invalid vulnerability results format: {str(e)}"}), 400
        
        # Save vulnerability results for the attack manager
        timestamp = int(time.time())
        vuln_results_file = os.path.join(REPORTS_DIR, f"vulnerability_input_{timestamp}.json")
        with open(vuln_results_file, 'w') as f:
            json.dump(vulnerability_results, f)
        
        # Reset status
        attack_status = {
            "status": "running", 
            "progress": 0, 
            "results": {},
            "start_time": time.time()
        }
        
        # Run attack in a thread
        attack_thread = threading.Thread(
            target=run_attack,
            args=(vulnerability_results,)
        )
        attack_thread.daemon = True
        attack_thread.start()
        
        return jsonify({"status": "started"})
    
    except Exception as e:
        print(f"Error handling attack request: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/api/attack/status', methods=['GET'])
def get_attack_status():
    global attack_status
    return jsonify(attack_status)

# API endpoint to get report files
@app.route('/api/reports', methods=['GET'])
def get_report_files():
    try:
        reports = []
        for filename in os.listdir(REPORTS_DIR):
            if filename.endswith(".html") or filename.endswith(".json"):
                file_path = os.path.join(REPORTS_DIR, filename)
                file_stat = os.stat(file_path)
                reports.append({
                    "filename": filename,
                    "path": f"/api/reports/{filename}",
                    "size": file_stat.st_size,
                    "created": file_stat.st_ctime
                })
        
        # Sort by creation time, newest first
        reports.sort(key=lambda x: x["created"], reverse=True)
        return jsonify(reports)
    
    except Exception as e:
        print(f"Error getting report files: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/api/reports/<path:filename>')
def get_report(filename):
    try:
        # Validate filename to prevent directory traversal attacks
        if '..' in filename or filename.startswith('/'):
            return jsonify({"error": "Invalid filename"}), 400
            
        return send_from_directory(REPORTS_DIR, filename)
    
    except Exception as e:
        print(f"Error getting report {filename}: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# Helper functions to run the Python scripts
def run_port_scan(target, ports="1-65535"):
    global scan_status
    
    try:
        # Build command
        cmd = ['python3', './python_modular_scanner_attack.py', target]
        if ports:
            cmd.extend(['-p', ports])
        
        # Create a unique output file for this scan
        timestamp = int(time.time())
        output_file = os.path.join(REPORTS_DIR, f"scan_results_{timestamp}.json")
        
        # Check if scanner script exists
        if not os.path.exists('./python_modular_scanner_attack.py'):
            raise FileNotFoundError("Scanner script not found")
        
        # Run the port scanner with output redirection
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1  # Line buffered
        )
        
        # Parse output in real time
        open_ports = {}
        
        for line in iter(process.stdout.readline, ''):
            # Update progress based on output
            if "[*] Progress:" in line:
                try:
                    progress_str = line.split("[*] Progress:")[1].split("%")[0].strip()
                    scan_status["progress"] = float(progress_str)
                except:
                    pass
            
            # Capture open ports
            if "TCP OPEN" in line:
                try:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+) - TCP OPEN - (\w+)', line)
                    if match:
                        ip, port, service = match.groups()
                        if ip not in open_ports:
                            open_ports[ip] = []
                        open_ports[ip].append([int(port), service])
                except Exception as e:
                    print(f"Error parsing port scan output line: {e}")
            
            print(line, end='')  # Print to server console
        
        # Check for stderr output
        stderr_output = process.stderr.read()
        if stderr_output:
            print(f"[ERROR] Port scanner stderr: {stderr_output}")
            scan_status["warnings"] = stderr_output
        
        # Wait for process to complete
        return_code = process.wait()
        
        if return_code != 0:
            scan_status["status"] = "error"
            scan_status["error"] = f"Scanner exited with code {return_code}"
            scan_status["end_time"] = time.time()
            return
        
        # Post-process results if not already added
        if not open_ports and os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    open_ports = json.load(f)
            except Exception as e:
                print(f"Error loading scan results from file: {e}")
        
        # If we didn't capture anything, create a minimal result
        if not open_ports and target:
            open_ports = {target: []}
        
        # Save results to output file
        try:
            with open(output_file, 'w') as f:
                json.dump(open_ports, f, indent=2)
        except Exception as e:
            print(f"Error saving scan results to file: {e}")
            scan_status["warnings"] = f"Could not save results to file: {str(e)}"
        
        # Update status
        scan_status["status"] = "completed"
        scan_status["progress"] = 100
        scan_status["results"] = open_ports
        scan_status["output_file"] = output_file
        scan_status["end_time"] = time.time()
        
    except Exception as e:
        print(f"Error running scan: {e}")
        scan_status["status"] = "error"
        scan_status["error"] = str(e)
        scan_status["end_time"] = time.time()

def run_vulnerability_assessment(scan_results):
    global vuln_status
    
    try:
        # Validate scan results format
        if not isinstance(scan_results, dict):
            raise ValueError("Scan results must be a dictionary")
        
        # Check if scan results are empty
        if not scan_results:
            vuln_status["status"] = "error"
            vuln_status["error"] = "Empty scan results"
            vuln_status["end_time"] = time.time()
            return
        
        # Validate structure of each entry
        for ip, ports in scan_results.items():
            if not isinstance(ip, str) or not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                raise ValueError(f"Invalid IP address format: {ip}")
            if not isinstance(ports, list):
                raise ValueError(f"Port list for {ip} must be an array")
        
        # Create a temporary file with scan results
        timestamp = int(time.time())
        input_file = os.path.join(REPORTS_DIR, f"scan_input_{timestamp}.json")
        with open(input_file, 'w') as f:
            json.dump(scan_results, f)
        
        # Build command to run vulnerability manager
        cmd = [
            'python3', './vulnerability_manager.py', 
            '--input-file', input_file, 
            '--output', REPORTS_DIR
        ]
        
        # Check if vulnerability manager script exists
        if not os.path.exists('./vulnerability_manager.py'):
            raise FileNotFoundError("Vulnerability manager script not found")
        
        # Run the vulnerability manager
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1  # Line buffered
        )
        
        # Look for the output file pattern in the logs
        vuln_output_file = None
        for line in iter(process.stdout.readline, ''):
            # Update progress based on output (assuming the script outputs progress)
            if "Progress:" in line:
                try:
                    progress_str = line.split("Progress:")[1].split("%")[0].strip()
                    vuln_status["progress"] = float(progress_str)
                except:
                    pass
            
            # Look for the output file path
            if "Results saved to:" in line and "JSON:" in line:
                try:
                    vuln_output_file = line.split("JSON:")[1].strip()
                except:
                    pass
            
            print(line, end='')  # Print to server console
        
        # Wait for process to complete
        process.wait()
        
        # Check for stderr output
        stderr_output = process.stderr.read()
        if stderr_output:
            print(f"[ERROR] Vulnerability manager stderr: {stderr_output}")
            vuln_status["warnings"] = stderr_output
        
        # Load results from the output file
        results = {}
        if vuln_output_file and os.path.exists(vuln_output_file):
            try:
                with open(vuln_output_file, 'r') as f:
                    results = json.load(f)
            except Exception as e:
                print(f"Error loading vulnerability results: {e}")
                vuln_status["status"] = "error"
                vuln_status["error"] = f"Error loading results: {str(e)}"
                vuln_status["end_time"] = time.time()
                return
        else:
            if process.returncode != 0:
                vuln_status["status"] = "error"
                vuln_status["error"] = f"Vulnerability manager failed with exit code {process.returncode}"
                vuln_status["end_time"] = time.time()
                return
        
        # Update status
        vuln_status["status"] = "completed"
        vuln_status["progress"] = 100
        vuln_status["results"] = results
        vuln_status["output_file"] = vuln_output_file
        vuln_status["end_time"] = time.time()
        
    except Exception as e:
        print(f"Error running vulnerability assessment: {e}")
        vuln_status["status"] = "error"
        vuln_status["error"] = str(e)
        vuln_status["end_time"] = time.time()

def run_attack(vulnerability_results):
    global attack_status
    
    try:
        # Extract vulnerable hosts and corresponding modules
        attacks_to_run = []
        for ip, data in vulnerability_results.items():
            if "vulnerabilities" in data:
                for vuln in data["vulnerabilities"]:
                    if vuln.get("is_vulnerable", False):
                        port = vuln.get("port")
                        service = vuln.get("service", "")
                        name = vuln.get("name", "")
                        
                        attacks_to_run.append({
                            "ip": ip,
                            "port": port,
                            "service": service,
                            "vulnerability": name,
                            "status": "pending"
                        })
        
        # Track progress
        total_attacks = len(attacks_to_run)
        if total_attacks == 0:
            attack_status["status"] = "completed"
            attack_status["progress"] = 100
            attack_status["results"] = {"attacks": []}
            attack_status["end_time"] = time.time()
            print("[*] No vulnerable hosts to attack")
            return
            
        completed_attacks = 0
        results = {"attacks": []}
        
        # Run each attack
        for attack in attacks_to_run:
            # Update attack status
            attack["status"] = "running"
            attack_status["progress"] = (completed_attacks / total_attacks) * 100
            
            try:
                # Use the port scanner's attack functionality directly
                from python_modular_scanner_attack import scan_and_attack
                
                ip = attack["ip"]
                port = attack["port"]
                
                # Execute attack with the execute_metasploit flag set to False for safety
                # Set to True only in controlled environments with proper permission
                success, attack_output = scan_and_attack(ip, port, execute_metasploit=False)
                
                # Update attack result
                attack["status"] = "completed" if success else "failed"
                attack["success"] = success
                attack["timestamp"] = time.time()
                attack["output"] = attack_output
                
            except Exception as e:
                attack["status"] = "error"
                attack["error"] = str(e)
                attack["output"] = f"Attack failed with error: {str(e)}"
            
            # Add to results
            results["attacks"].append(attack)
            completed_attacks += 1
            
            # Update progress
            attack_status["progress"] = (completed_attacks / total_attacks) * 100
        
        # Save results to file
        timestamp = int(time.time())
        output_file = os.path.join(REPORTS_DIR, f"attack_results_{timestamp}.json")
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Generate HTML report
        html_report = os.path.join(REPORTS_DIR, f"attack_report_{timestamp}.html")
        generate_attack_report(results, html_report)
        
        # Update status
        attack_status["status"] = "completed"
        attack_status["progress"] = 100
        attack_status["results"] = results
        attack_status["output_file"] = output_file
        attack_status["html_report"] = html_report
        attack_status["end_time"] = time.time()
        
    except Exception as e:
        print(f"Error running attacks: {e}")
        attack_status["status"] = "error"
        attack_status["error"] = str(e)
        attack_status["end_time"] = time.time()

def generate_attack_report(results, output_file):
    """Generate an HTML report for attack results"""
    try:
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Attack Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px 5px 0 0; }}
        .header h1 {{ margin: 0; }}
        .summary {{ background-color: #ecf0f1; padding: 15px; border-radius: 0 0 5px 5px; margin-bottom: 20px; }}
        .attack {{ background-color: white; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px; }}
        .attack-header {{ background-color: #3498db; color: white; padding: 10px 15px; border-radius: 5px 5px 0 0; }}
        .attack-header.success {{ background-color: #2ecc71; }}
        .attack-header.failure {{ background-color: #e74c3c; }}
        .attack-content {{ padding: 15px; }}
        .attack pre {{ background-color: #2c3e50; color: #ecf0f1; padding: 10px; overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 15px; }}
        th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Attack Report</h1>
        </div>
        <div class="summary">
            <p>Report generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Total attacks attempted: {len(results['attacks'])}</p>
            <p>Successful attacks: {sum(1 for a in results['attacks'] if a.get('success', False))}</p>
        </div>
"""
        
        # Add attack details
        for attack in results['attacks']:
            status_class = "success" if attack.get('success', False) else "failure"
            status_text = "SUCCESS" if attack.get('success', False) else "FAILED"
            
            # Escape HTML in attack output to prevent XSS
            output = attack.get('output', 'No output available')
            output = output.replace("<", "&lt;").replace(">", "&gt;")
            
            html += f"""
        <div class="attack">
            <div class="attack-header {status_class}">
                <h2>{attack.get('vulnerability', 'Unknown Vulnerability')} ({status_text})</h2>
            </div>
            <div class="attack-content">
                <p><strong>Target:</strong> {attack.get('ip')}:{attack.get('port')} ({attack.get('service', 'unknown')})</p>
                <h3>Attack Output</h3>
                <pre>{output}</pre>
            </div>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html)
        
        return output_file
    
    except Exception as e:
        print(f"Error generating attack report: {e}")
        return None

if __name__ == '__main__':
    # Create output directories
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # Run with debug enabled but no remote connections by default for security
    # Change host to '0.0.0.0' only in trusted environments
    app.run(host='127.0.0.1', port=5000, debug=True)