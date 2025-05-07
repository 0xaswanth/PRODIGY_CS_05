# PRODIGY_CS_05

# Network Packet Analyzer

## Description
This tool is a simple packet sniffer that captures and analyzes network packets. It provides details such as:
- Source and destination IP addresses
- Protocol used (TCP, UDP, ICMP, etc.)
- Payload data (if applicable)

This tool is designed for educational purposes and should only be used in controlled environments or with permission to capture network traffic.

## Features
- Displays real-time packet information (source IP, destination IP, protocol, and payload).
- Saves captured packet data to a text file for later analysis.
- Supports multiple network interfaces based on your system configuration.

## Requirements
- Python 3.x
- Scapy
- Colorama (for colored output)

## Installation
1. Clone or download this repository.
2. Install the necessary Python packages:
   ```bash
   pip install scapy colorama
   ```

## Usage
1. Run the script.
   ```bash
   python packet_sniffer.py
   ```
2. The script will list available network interfaces on your system. Choose the interface you want to monitor (e.g., Wi-Fi).
3. The script will start sniffing packets and display relevant information such as:
   - Source IP -> Destination IP
   - Protocol
   - Payload (if applicable)
4. All captured packets are saved to `captured_packets.txt`.

## Ethical Disclaimer
This tool should only be used for educational purposes and in environments where you have explicit permission to capture network traffic.

## License
This tool is released under the MIT License.

