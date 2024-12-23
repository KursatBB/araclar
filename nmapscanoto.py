import os
import re
import subprocess
import argparse

def parse_input_file(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    subnets = []
    hosts = []
    ip_ports = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if re.match(r"\d+\.\d+\.\d+\.\d+/\d+", line):
            subnets.append(line)
        elif re.match(r"\d+\.\d+\.\d+\.\d+:\d+", line):
            ip_ports.append(line)
        elif re.match(r"\d+\.\d+\.\d+\.\d+", line):
            hosts.append(line)

    return subnets, hosts, ip_ports

def run_nmap(target, mode, port=None, output_file=None):
    if mode == "subnet":
        command = [
            "nmap", "-sC", "-sV", target,
            "--script", "ssl-enum-ciphers,ssl-cert,smb-security-mode,smb2-security-mode"
        ]
    elif mode == "host":
        command = [
            "nmap", "-sC", "-sV", target,
            "--script", "ssl-enum-ciphers,ssl-cert,smb-security-mode,smb2-security-mode"
        ]
    elif mode == "ip_port":
        command = [
            "nmap", "-sC", "-sV", target, "-p", port,
            "--script", "ssl-enum-ciphers,ssl-cert,smb-security-mode,smb2-security-mode"
        ]
    else:
        raise ValueError("Invalid mode")

    if output_file:
        command.extend(["-oN", output_file])

    print(f"Running: {' '.join(command)}")
    subprocess.run(command)

def main():
    parser = argparse.ArgumentParser(description="Automated Nmap Scanner")
    parser.add_argument("-i", "--input", required=True, help="Input file containing targets")
    parser.add_argument("-o", "--output", required=True, help="Output file for results")
    args = parser.parse_args()

    input_file = args.input
    output_file = args.output

    if not os.path.exists(input_file):
        print(f"Error: File {input_file} does not exist.")
        return

    subnets, hosts, ip_ports = parse_input_file(input_file)

    with open(output_file, 'w') as output:
        for subnet in subnets:
            subnet_output_file = f"{subnet.replace('/', '_')}_results.txt"
            run_nmap(subnet, "subnet", output_file=subnet_output_file)
            with open(subnet_output_file, 'r') as subnet_output:
                output.write(subnet_output.read())

        for host in hosts:
            temp_file = f"{host}_temp.txt"
            run_nmap(host, "host", output_file=temp_file)
            with open(temp_file, 'r') as temp:
                output.write(temp.read())
            os.remove(temp_file)

        for ip_port in ip_ports:
            ip, port = ip_port.split(":")
            temp_file = f"{ip}_{port}_temp.txt"
            run_nmap(ip, "ip_port", port, output_file=temp_file)
            with open(temp_file, 'r') as temp:
                output.write(temp.read())
            os.remove(temp_file)

if __name__ == "__main__":
    main()
