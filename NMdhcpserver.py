#!/usr/bin/env python3

# Dustin Marchak
# CSCI 5180 - Midterm Lab
# NMdhcpserver.py - Configure IPv4 Host DHCP pools on R5 for R2-F0/0, R3-F0/0, and R4-F0/0

# imports
import re
import time
from netmiko import ConnectHandler, redispatch

# Function Definitions

# Discover R5's IPv6 address from R4 using CDP neighbors.
def get_r5_ipv6(connection):

    # Run 'show cdp neighbors detail' on R4 to get neighbor addresses.
    output = connection.send_command("show cdp neighbors detail")

    # Split CDP output into per-neighbor sections (separated by long dash lines).
    sections = re.split(r'-{20,}', output)

    for section in sections:
        # Look for the section that belongs to R5.
        if not re.search(r'Device ID:\s*R5', section, re.IGNORECASE):
            continue

        # Extract all IPv6 addresses from R5's CDP entry.
        ipv6_addrs = re.findall(r'IPv6 address:\s*([0-9a-fA-F:]+)', section)

        # Prefer a global unicast address over link-local.
        for addr in ipv6_addrs:
            if not addr.lower().startswith('fe80'):
                return addr

        # return link-local if no global address was found.
        for addr in ipv6_addrs:
            return addr


def ssh_to_r5(connection, r5_ipv6):
    # From R4's CLI, SSH into R5 using its IPv6 address and redispatch the Netmiko connection to send commands to R5.

    # SSH credentials
    username = "cisco"
    password = "cisco"

    # SSH from R4's CLI to R5 IPv6 address
    connection.write_channel(f"ssh -l {username} {r5_ipv6}\n")
    time.sleep(2)

    # Read the output and look for the password prompt from R5
    output = connection.read_channel()
    if "Password:" in output or "password:" in output:
        connection.write_channel(f"{password}\n")
        time.sleep(2)

    # redispatch netmiko connection so it knows R4 is now connected to R5
    redispatch(connection, device_type="cisco_ios")

def cleanup_duplicate_bindings(connection):
    
    # R4 was pulling multiple active DHCP leases, this function checks for duplicates and removes them.
    bindings = connection.send_command("show ip dhcp binding")

    # Parse each DHCP binding line
    entries = re.findall(
        r'^(\d+\.\d+\.\d+\.\d+)\s+(\S+)',
        bindings, re.MULTILINE
    )

    # Group bindings by client-ID
    client_bindings = {}
    for ip, client_id in entries:
        # if the client ID is not in the client bindings dict, add it.
        if client_id not in client_bindings:
            client_bindings[client_id] = []
        client_bindings[client_id].append(ip)

    # For each client-ID that has more than one binding, clear all but the first (oldest) lease using the exec command 'clear ip dhcp binding <ip>'.
    for client_id, ips in client_bindings.items():
        if len(ips) <= 1:
            continue
        # Keep the first entry (oldest), clear the rest (newer duplicates).
        duplicates = ips[1:]
        print(f"  Clearing {len(duplicates)} duplicate lease(s) for client {client_id}")
        for dup_ip in duplicates:
            connection.send_command_timing(f"clear ip dhcp binding {dup_ip}")

def configure_dhcp(connection):
    #Configure DHCP pools on R5 (already connected via redispatch)

    # client id (01+MAC addresses) for static DHCP host pools (found using NMtcpdump.py)
    r2_f0_client_id = "01ca.0231.b100.00"
    r3_f0_client_id = "01ca.0331.c000.00"

    # Get R5 hostname to show we're on the right device
    hostname = connection.find_prompt().rstrip('#>')
    print(f"  Connected to {hostname}")

    # Build the DHCP configuration command list.  
    dhcp_config = [
        # Exclude R5's own IP from the dynamic pool so it is never handed out.
        "ip dhcp excluded-address 10.0.0.5",

        # Host pool for R2-F0/0
        "ip dhcp pool R2-F0/0",
        "host 10.0.0.2 255.255.255.0",
        f"client-identifier {r2_f0_client_id}",
        "default-router 10.0.0.5",

        # Host pool for R3-F0/0
        "ip dhcp pool R3-F0/0",
        "host 10.0.0.3 255.255.255.0",
        f"client-identifier {r3_f0_client_id}",
        "default-router 10.0.0.5",

        # Dynamic pool for R4
        "ip dhcp pool R4-DYNAMIC",
        "network 10.0.0.0 255.255.255.0",
        "default-router 10.0.0.5",
    ]

    # send dhcp configurations
    connection.send_config_set(dhcp_config)
    print(f"  DHCP pools configured on {hostname}")

    # Clean up any duplicate leases for R4
    cleanup_duplicate_bindings(connection)

    # Retrieve the current DHCP bindings
    bindings = connection.send_command("show ip dhcp binding")

    # Parse IP addresses from the binding table output.
    client_ips = re.findall(r'^(\d+\.\d+\.\d+\.\d+)', bindings, re.MULTILINE)

    return client_ips, bindings


def main():
    # R4's management IPv4 address
    r4_ip = "198.51.100.4"

    # SSH credentials for R4
    username = "cisco"
    password = "cisco"

    # Step 1: SSH to R4 (IPv4)
    print(f"\nConnecting to R4 ({r4_ip})...")
    r4_device = {
        "device_type": "cisco_ios",
        "host": r4_ip,
        "username": username,
        "password": password,
    }
    connection = ConnectHandler(**r4_device)
    print(f"  Connected to {connection.find_prompt().rstrip('#>')}")

    # Step 2: Discover R5's IPv6 address from R4's CDP neighbors
    print("\nDiscovering R5's IPv6 address via CDP...")
    r5_ipv6 = get_r5_ipv6(connection)

    if not r5_ipv6:
        print("  Error: Could not discover R5's IPv6 address from R4's CDP neighbors.")
        connection.disconnect()
        return []

    print(f"  R5 IPv6 address: {r5_ipv6}")

    # Step 3: From R4, SSH into R5 using the discovered IPv6 address since NETMAN VM cannot route to R5 IPv6 address
    print(f"\nSSH from R4 to R5 ({r5_ipv6})...")
    ssh_to_r5(connection, r5_ipv6)

    # Step 4: Configure DHCP pools on R5 through the tunneled connection
    print("\nConfiguring DHCP pools on R5...")
    client_ips, bindings = configure_dhcp(connection)

    # Step 5: Display DHCP bindings and return the list of client IPs
    print(f"\nDHCP Bindings on R5:\n{bindings}")

    print("\nDHCPv4 client IP addresses:")
    if client_ips:
        for ip in client_ips:
            print(f"  {ip}")
    else:
        print("  No active bindings yet (clients have not requested addresses)")

    # Exit R5 (back to R4's CLI) and disconnect from R4
    connection.write_channel("exit\n")
    time.sleep(1)
    connection.disconnect()


# namespace check
if __name__ == "__main__":
    main()
