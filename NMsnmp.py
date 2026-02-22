#!/usr/bin/env python3

# Dustin Marchak
# CSCI 5180 - Midterm Lab
# NMsnmp.py - Use SNMP to get interface addresses and status from all five routers.
# Monitor CPU utilization of R1 for 2 minutes every 5 seconds and plot.

# imports
import json
import time
import asyncio
import ipaddress
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from puresnmp import Client, V2C, PyWrapper

# Function Definitions

# SNMP OID constants
OID_IF_DESCR       = "1.3.6.1.2.1.2.2.1.2"       # ifDescr - interface names
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"       # ifOperStatus - 1=up, 2=down
OID_IP_IF_INDEX    = "1.3.6.1.2.1.4.20.1.2"       # ipAdEntIfIndex - maps IPv4 addr to ifIndex
OID_IP_NET_MASK    = "1.3.6.1.2.1.4.20.1.3"       # ipAdEntNetMask - subnet mask
OID_IPADDR_IFINDEX = "1.3.6.1.2.1.4.34.1.3"       # ipAddressIfIndex (IP-MIB, RFC 4293)
OID_IPADDR_PREFIX  = "1.3.6.1.2.1.4.34.1.5"       # ipAddressPrefix (IP-MIB, RFC 4293)
OID_CPU_5SEC       = "1.3.6.1.4.1.9.9.109.1.1.1.1.6.1"  # cpmCPUTotal5secRev (CISCO-PROCESS-MIB, CPU index 1)

# SNMP community string
COMMUNITY = "PUBLIC"


def make_client(ip):
    # Create a puresnmp PyWrapper client for the given router IP.
    return PyWrapper(Client(ip, V2C(COMMUNITY)))


async def walk(client, oid):
    # Walk an OID tree. Returns list of (oid_string, value) tuples.
    results = []
    async for varbind in client.walk(oid):
        results.append((varbind.oid, varbind.value))
    return results


async def get_interface_map(client):
    # Walk ifDescr to build {ifIndex: interface_name} mapping.
    if_map = {}
    for oid, value in await walk(client, OID_IF_DESCR):
        if_index = oid.split(".")[-1]
        # puresnmp returns bytes for OctetString values, decode to str
        if_map[if_index] = value.decode() if isinstance(value, bytes) else str(value)
    return if_map


async def get_interface_status(client, if_map):
    # Walk ifOperStatus. Returns {interface_name: "up"/"down"} dict.
    status_map = {}
    for oid, value in await walk(client, OID_IF_OPER_STATUS):
        if_index = oid.split(".")[-1]
        if_name = if_map.get(if_index, f"ifIndex-{if_index}")
        # ifOperStatus: 1=up, 2=down
        status_map[if_name] = "up" if int(value) == 1 else "down"
    return status_map


async def get_ipv4_addresses(client, if_map):
    # Walk ipAdEntIfIndex and ipAdEntNetMask to collect IPv4 addresses per interface.
    # Returns {interface_name: "x.x.x.x/prefix"} dict.

    # Map each IPv4 address to its ifIndex
    addr_to_if = {}
    for oid, value in await walk(client, OID_IP_IF_INDEX):
        ipv4_addr = ".".join(oid.split(".")[-4:])
        addr_to_if[ipv4_addr] = str(int(value))

    # Map each IPv4 address to its subnet mask
    addr_to_mask = {}
    for oid, value in await walk(client, OID_IP_NET_MASK):
        ipv4_addr = ".".join(oid.split(".")[-4:])
        # Subnet mask may be returned as bytes (4 octets) or dotted string
        if isinstance(value, bytes) and len(value) == 4:
            mask = ".".join(str(b) for b in value)
        else:
            mask = str(value)
        addr_to_mask[ipv4_addr] = mask

    # Build per-interface address dict
    ipv4_by_iface = {}
    for addr, if_index in addr_to_if.items():
        if_name = if_map.get(if_index, f"ifIndex-{if_index}")
        mask = addr_to_mask.get(addr, "255.255.255.0")
        prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
        ipv4_by_iface[if_name] = f"{addr}/{prefix}"

    return ipv4_by_iface


async def get_ipv6_addresses(client, if_map):
    # Walk IP-MIB ipAddressTable to collect IPv6 addresses per interface.
    # OID index format: ipAddressIfIndex.<addrType>.<addrLen>.<addr octets...>
    # addrType: 1=IPv4, 2=IPv6, 4=IPv6z (with zone)
    # Returns {interface_name: "xxxx::xxxx/prefix"} dict.

    base_if = OID_IPADDR_IFINDEX + "."
    base_pfx = OID_IPADDR_PREFIX + "."

    # Walk ipAddressIfIndex to find IPv6 addresses and their ifIndex
    ipv6_entries = {}  # key: addr_index_suffix -> (ipv6_addr, if_index)
    for oid, value in await walk(client, OID_IPADDR_IFINDEX):
        if not oid.startswith(base_if):
            continue
        index = oid[len(base_if):]
        parts = index.split(".")
        addr_type = int(parts[0])

        # Only process IPv6 (type 2) and skip link-local (fe80)
        if addr_type != 2:
            continue
        addr_len = int(parts[1])
        if addr_len != 16 or len(parts) < 18:
            continue

        addr_bytes = bytes(int(o) for o in parts[2:18])
        ipv6_addr = ipaddress.IPv6Address(addr_bytes)

        # Skip link-local addresses
        if ipv6_addr.is_link_local:
            continue

        ipv6_entries[index] = (ipv6_addr, str(int(value)))

    # Walk ipAddressPrefix to get prefix lengths for each IPv6 address
    prefix_map = {}  # key: addr_index_suffix -> prefix_len
    for oid, value in await walk(client, OID_IPADDR_PREFIX):
        if not oid.startswith(base_pfx):
            continue
        index = oid[len(base_pfx):]
        # The value is an OID reference whose last element is the prefix length
        prefix_len = str(value).split(".")[-1]
        prefix_map[index] = prefix_len

    # Build per-interface IPv6 address dict
    ipv6_by_iface = {}
    for index, (ipv6_addr, if_index) in ipv6_entries.items():
        if_name = if_map.get(if_index, f"ifIndex-{if_index}")
        prefix_len = prefix_map.get(index, "64")
        ipv6_by_iface[if_name] = f"{ipv6_addr}/{prefix_len}"

    return ipv6_by_iface


async def query_router(name, ip):
    # Query a single router for all interface addresses and status via SNMP.
    print(f"  Querying {name} ({ip})...")

    client = make_client(ip)
    if_map = await get_interface_map(client)
    interfaces = await get_interface_status(client, if_map)
    ipv4_addrs = await get_ipv4_addresses(client, if_map)
    ipv6_addrs = await get_ipv6_addresses(client, if_map)

    # Merge IPv4 and IPv6 into combined addresses dict
    addresses = {}
    for iface in sorted(set(list(ipv4_addrs.keys()) + list(ipv6_addrs.keys()))):
        entry = {}
        if iface in ipv4_addrs:
            entry["v4"] = ipv4_addrs[iface]
        if iface in ipv6_addrs:
            entry["v6"] = ipv6_addrs[iface]
        addresses[iface] = entry

    return {"addresses": addresses, "interfaces": interfaces}


async def monitor_cpu(ip, duration=120, interval=5):
    # Poll R1's CPU utilization every 'interval' seconds for 'duration' seconds.
    # Plot the data as a line graph and save as cpu_utilization.jpg.
    print(f"\nMonitoring CPU utilization on {ip} for {duration} seconds...")

    client = make_client(ip)
    timestamps = []
    cpu_values = []
    num_samples = (duration // interval) + 1
    start_time = time.time()

    for i in range(num_samples):
        # Calculate the exact target time for this sample
        target_time = start_time + (i * interval)
        elapsed = i * interval

        try:
            cpu_pct = int(await client.get(OID_CPU_5SEC))
            timestamps.append(elapsed)
            cpu_values.append(cpu_pct)
            print(f"  {elapsed:6.1f}s - CPU: {cpu_pct}%")
        except Exception:
            print(f"  {elapsed:6.1f}s - CPU: read error")

        # Sleep only the remaining time until the next 5-second mark
        sleep_time = target_time + interval - time.time()
        if sleep_time > 0:
            await asyncio.sleep(sleep_time)

    # Plot the CPU utilization data
    plt.figure(figsize=(10, 5))
    plt.plot(timestamps, cpu_values, marker="o", linewidth=2, markersize=4)
    plt.title("R1 CPU Utilization (5-Second Average)")
    plt.xlabel("Time (seconds)")
    plt.ylabel("CPU Utilization (%)")
    plt.ylim(0, 100)
    plt.grid(True)
    plt.tight_layout()

    output_file = "cpu_utilization.jpg"
    plt.savefig(output_file, format="jpg", dpi=150)
    plt.close()
    print(f"  CPU graph saved to {output_file}")


async def main():
    # Router management IPs
    routers = {
        "R1": "10.0.1.1",
        "R2": "10.0.0.2",
        "R3": "10.0.0.3",
        "R4": "198.51.100.4",
        "R5": "10.0.0.5",
    }

    # Step 1: Query all routers for interface addresses and status via SNMP
    print("\nQuerying routers via SNMP...")
    all_results = {}
    for name, ip in routers.items():
        all_results[name] = await query_router(name, ip)

    # Step 2: Write results to JSON file
    output_file = "snmp_query_results.txt"
    with open(output_file, "w") as f:
        json.dump(all_results, f, indent=4)
    print(f"\nResults saved to {output_file}")

    # Step 3: Monitor R1 CPU utilization for 2 minutes at 5-second intervals
    await monitor_cpu(routers["R1"])


# namespace check
if __name__ == "__main__":
    asyncio.run(main())
