#!/usr/bin/env python3

# Dustin Marchak
# CSCI 5180 - Midterm Lab
# NMtcpdump.py - Parse a .pcap file and extract MAC addresses of R2-F0/0 and R3-F0/0.

# imports
import re
import pyshark
from netmiko import ConnectHandler

# Function Definitions

# Parse the packet capture for ICMP request source IP addresses
def parse_pcap(pcap_path):
    
    # Use a set to prevent duplicate IP addresses.
    discovered_ips = set()

    # Use a display filter to only return ICMP echo request packets (type 8)
    capture = pyshark.FileCapture(pcap_path, display_filter='icmp.type==8')

    # Iterate over every ICMP echo request packet in the capture file and record the src IP
    # the source IP of an ICMP request will always be the device that originally sent it
    for packet in capture:
        discovered_ips.add(packet.ip.src)

    # Close the capture to release the TShark subprocess and file handles.
    capture.close()

    # Return all unique source IPs that sent ICMP requests.
    return discovered_ips

def ssh_get_hostname_and_mac(ip, interface="FastEthernet0/0"):

    # SSH credentials for the routers
    SSH_USERNAME = "cisco"
    SSH_PASSWORD = "cisco"
    
    # Define the connection parameters
    device = {
        "device_type": "cisco_ios",
        "host": ip,
        "username": SSH_USERNAME,
        "password": SSH_PASSWORD,
    }

    try:
        # Establish the SSH connection to the router.
        connection = ConnectHandler(**device)

        # get the hostname of the device
        hostname = connection.find_prompt().rstrip('#>')

        # Send the 'show interface' command and wait for the output.
        output = connection.send_command(f"show interface {interface}")

        # close the SSH session
        connection.disconnect()

        # Use regex to find the MAC address in Cisco's format.
        mac_match = re.search(
            r'address is ([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})',
            output
        )

        # If the regex matched, return the hostname and MAC address string.
        if mac_match:
            return hostname, mac_match.group(1)
        else:
            return hostname, "Could not parse MAC from output"

    # Catch exceptions
    except Exception as e:
        return ip, f"Error: {e}"

def main():
    # pcap file path
    pcap_path = "capture.pcap"

    # Parse the pcap file to discover all IP addresses
    print(f"\nParsing '{pcap_path}' for IP addresses...")
    discovered_ips = parse_pcap(pcap_path)

    # Display all source IPs found in ICMP requests, sorted for readability.
    print(f"    Discovered router IPs: {', '.join(sorted(discovered_ips))}")

    # SSH into each discovered router
    print("\nConnecting to routers via Netmiko to retrieve "
          "FastEthernet0/0 MAC addresses...\n")

    for ip in sorted(discovered_ips):
        # SSH into the router, retrieve its hostname and MAC address.
        print(f"  {ip}: Connecting via SSH...")
        hostname, mac = ssh_get_hostname_and_mac(ip)
        # Display the hostname and retrieved MAC address (or error message).
        print(f"  {hostname} ({ip}) FastEthernet0/0 MAC: {mac}")
        print()

# namespace check
if __name__ == "__main__":
    main()
