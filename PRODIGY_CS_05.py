import os
import sys

# Try importing scapy and handle missing package error
try:
    from scapy.all import sniff, TCP, IP
except ModuleNotFoundError:
    print("Error: 'scapy' module is not installed. Please install it using:")
    print("       pip install scapy")
    sys.exit(1)

# Check if the script is run as administrator/root
if os.name == "nt":  # Windows
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Error: This script must be run as an administrator.")
        sys.exit(1)
elif os.geteuid() != 0:  # Linux/macOS
    print("Error: This script must be run as root (use 'sudo').")
    sys.exit(1)

# Disclaimer and terms of use
print("------------------------ Packet Sniffer Tool Disclaimer ---------------------------")
print("This packet sniffer tool is intended for educational and ethical purposes only.")
print("Unauthorized use, distribution, or modification of this tool is strictly prohibited.")
print("By using this tool, you agree to the following terms and conditions:")
print("\n1. You will only use this tool on networks and systems for which you have explicit permission.")
print("2. You will not use this tool to violate any laws, regulations, or terms of service.")
print("3. You will not use this tool to harm, disrupt, or exploit any networks or systems.")
print("4. You will not use this tool to intercept, collect, or store any sensitive or confidential information.")
print("5. You will not redistribute or sell this tool without the express permission of the author.")
print("6. The author is not responsible for any damages or losses incurred as a result of using this tool.")
print("7. You will respect the privacy and security of all networks and systems you interact with using this tool.")

accept_terms = input("\nDo you accept these terms and conditions? (y/n): ")

if accept_terms.lower() != 'y':
    print("You must accept the terms and conditions before using this tool.")
    sys.exit()

print("\n--------------- Packet Sniffing Tool ---------------")

# Defines a function to display and save the captured packets
def packet_sniff(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = packet[IP].proto
        payload = packet[TCP].payload.load if hasattr(packet[TCP].payload, 'load') else "No Payload"

        output_string = f"Source IP: {src_ip}\n"
        output_string += f"Destination IP: {dst_ip}\n"
        output_string += f"Source Port: {src_port}\n"
        output_string += f"Destination Port: {dst_port}\n"
        output_string += f"Protocol: {protocol}\n"
        output_string += f"Payload: {str(payload)[:50]}...\n"

        print(output_string)
        with open('packet_sniffer_results.txt', 'a') as f:
            f.write(output_string + "\n")

# Sets the path and filename for the output text file
output_file = "packet_sniffer_results.txt"

# Calls the sniff() function from the Scapy library to capture and analyze network packets
try:
    sniff(filter="tcp", prn=packet_sniff, store=0, count=10)
except PermissionError:
    print("Error: Permission denied. Run this script as an administrator/root user.")
    sys.exit(1)
except Exception as e:
    print(f"An error occurred: {e}")
    sys.exit(1)

# Displays the output file's name and location after successful sniffing
print(f"\nResults saved to: {output_file}")
