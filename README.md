# CSCI 5180 - Midterm Lab
**Dustin Marchak**

Network Management & Automation scripts for a GNS3 lab topology with five Cisco c7200 routers (R1-R5).

## Python Scripts

### NMtcpdump.py
Parses a packet capture file (`capture.pcap`) using PyShark to discover router IP addresses from ICMP echo requests. Then SSHes into each discovered router via Netmiko to retrieve the hostname and FastEthernet0/0 MAC address.

**Dependencies:** `pyshark`, `netmiko`

### NMdhcpserver.py
Configures R5 as a DHCPv4 server by SSHing to R4, discovering R5's IPv6 address via CDP, then hopping from R4 to R5 over SSH (jump host pattern using Netmiko's `redispatch`). Creates DHCP host pools for R2-F0/0 and R3-F0/0 (bound by client-identifier) and a dynamic pool for R4-F0/0. Includes duplicate lease cleanup.

**Dependencies:** `netmiko`

### NMsnmp.py
Queries all five routers via SNMP using PureSNMP to collect IPv4/IPv6 addresses and interface status. Saves the results as JSON to `snmp_query_results.txt`. Then monitors R1's CPU utilization for 2 minutes at 5-second intervals and plots the data as a line graph saved to `cpu_utilization.jpg`.

**Dependencies:** `puresnmp`, `matplotlib`

### NMgithub.py
Creates a GitHub repository using the GitHub REST API and pushes files using GitPython. First pushes the SNMP output files (`.txt`, `.jpg`), then detects and pushes any locally modified files by comparing against the remote.

**Dependencies:** `gitpython`, `requests`

## Output Files

| File | Description |
|------|-------------|
| `snmp_query_results.txt` | JSON containing IPv4/IPv6 addresses and interface status for all 5 routers |
| `cpu_utilization.jpg` | Line graph of R1 CPU utilization over 2 minutes |

## Input Files

| File | Description |
|------|-------------|
| `capture.pcap` | Packet capture used by NMtcpdump.py to discover router IPs |

## Router Topology

| Router | Management IP | Role |
|--------|--------------|------|
| R1 | 10.0.1.1 | DHCP Server (IPv4 & IPv6) |
| R2 | 10.0.0.2 | DHCP client (static host pool) |
| R3 | 10.0.0.3 | DHCP client (static host pool) |
| R4 | 198.51.100.4 | DHCP client (dynamic pool), jump host to R5, IPv6 SLAAC provider |
| R5 | 10.0.0.5 | DHCP server |
