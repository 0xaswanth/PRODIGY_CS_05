# Import necessary libraries
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.sendrecv import sniff
from datetime import datetime
from colorama import Fore, init
import subprocess

# Initialize colorama for colored output
init(autoreset=True)

# Print header
def print_header():
    print(Fore.CYAN + '='*50)
    print(Fore.CYAN + '      🌐 Network Packet Analyzer 🌐')
    print(Fore.CYAN + '='*50)
    print(Fore.RED + '[!] Ethical Use Disclaimer: This tool should only be used in a controlled, educational environment or with permission to capture network traffic.')

# Save packet details to a text file
def save_to_file(data, filename='captured_packets.txt'):
    with open(filename, 'a') as file:
        file.write(data + '\n')

# Get interface mappings from Get-NetAdapter
def get_interface_mappings():
    interfaces = {}
    try:
        result = subprocess.run(['C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', '-Command', 'Get-NetAdapter | Select-Object -Property Name, InterfaceDescription'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        for line in lines[3:]:
            if line.strip():
                parts = line.split()
                name = parts[0]
                description = ' '.join(parts[1:])
                interfaces[name] = description
    except Exception as e:
        print(Fore.RED + f'[!] Error fetching interfaces: {e}')
    return interfaces

# Analyze each packet
def analyze_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(protocol, 'OTHER')

        packet_info = f'{timestamp} | {src_ip} -> {dst_ip} | Protocol: {proto_name}'
        print(Fore.YELLOW + packet_info)

        payload = b''
        if proto_name == 'TCP' and TCP in packet:
            payload = bytes(packet[TCP].payload)
        elif proto_name == 'UDP' and UDP in packet:
            payload = bytes(packet[UDP].payload)
        elif proto_name == 'ICMP' and ICMP in packet:
            payload = bytes(packet[ICMP].payload)

        if payload:
            try:
                data = payload.decode('utf-8', errors='ignore')
                print(Fore.GREEN + f'    Payload: {data[:100]}')
                save_to_file(packet_info + f' | Payload: {data[:100]}')
            except:
                print(Fore.RED + '    [!] Cannot decode payload.')
                save_to_file(packet_info + ' | Payload: Cannot decode.')
        else:
            save_to_file(packet_info)
    else:
        print(Fore.LIGHTBLACK_EX + 'Non-IP packet captured.')

# Start sniffing packets
def start_sniffing(interface_name):
    print_header()
    interfaces = get_interface_mappings()
    device_name = interfaces.get(interface_name, interface_name)
    if not device_name:
        print(Fore.RED + f'[!] Interface "{interface_name}" not found!')
        return
    print(Fore.MAGENTA + f'[*] Sniffing on interface: {device_name}')
    try:
        sniff(filter='ip', iface=device_name, prn=analyze_packet, store=False)
    except PermissionError:
        print(Fore.RED + '[!] Run this script as Administrator.')
    except Exception as e:
        print(Fore.RED + f'[!] Error: {e}')

# Main block
if __name__ == '__main__':
    print('Available interfaces on your system:\n')
    interfaces = get_interface_mappings()
    for name, desc in interfaces.items():
        print(f'- {name}: {desc}')

    chosen_interface = input('\nEnter your network interface name from above: ')
    start_sniffing(chosen_interface)
