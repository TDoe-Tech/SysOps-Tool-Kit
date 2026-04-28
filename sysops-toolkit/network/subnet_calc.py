"""
network/subnet_calc.py
CompTIA Network+ Module — Subnet Calculator

Demonstrates: Subnetting, CIDR notation, IPv4 addressing, broadcast/network
addresses, usable host ranges — core Network+ exam objectives.
"""

import ipaddress
import argparse


def calculate_subnet(cidr: str) -> dict:
    """
    Calculate full subnet details from a CIDR address.

    Args:
        cidr: e.g. "192.168.1.0/24" or "10.0.0.0/8"

    Returns:
        dict with network info, host range, broadcast, etc.
    """
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError as e:
        return {"error": str(e)}

    hosts = list(net.hosts())
    usable_count = len(hosts)

    return {
        "input": cidr,
        "network_address": str(net.network_address),
        "broadcast_address": str(net.broadcast_address),
        "subnet_mask": str(net.netmask),
        "wildcard_mask": str(net.hostmask),
        "prefix_length": net.prefixlen,
        "total_addresses": net.num_addresses,
        "usable_hosts": usable_count,
        "first_host": str(hosts[0]) if hosts else "N/A",
        "last_host": str(hosts[-1]) if hosts else "N/A",
        "ip_class": _get_ip_class(str(net.network_address)),
        "is_private": net.is_private,
        "supernet": str(net.supernet()),
    }


def _get_ip_class(ip: str) -> str:
    """Determine legacy IP class (A/B/C/D/E) for educational context."""
    first_octet = int(ip.split(".")[0])
    if 1 <= first_octet <= 126:
        return "A"
    elif 128 <= first_octet <= 191:
        return "B"
    elif 192 <= first_octet <= 223:
        return "C"
    elif 224 <= first_octet <= 239:
        return "D (Multicast)"
    elif 240 <= first_octet <= 255:
        return "E (Reserved)"
    return "Unknown"


def split_subnet(cidr: str, new_prefix: int) -> list:
    """
    Split a network into subnets of a given prefix length.

    Args:
        cidr: Parent network e.g. "192.168.1.0/24"
        new_prefix: New prefix length e.g. 26

    Returns:
        List of subnet dicts
    """
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        subnets = list(net.subnets(new_prefix=new_prefix))
        return [calculate_subnet(str(s)) for s in subnets[:16]]  # cap at 16
    except ValueError as e:
        return [{"error": str(e)}]


def print_subnet_table(info: dict):
    """Pretty-print subnet info to terminal."""
    if "error" in info:
        print(f"[ERROR] {info['error']}")
        return

    print("\n" + "=" * 50)
    print(f"  Subnet Analysis: {info['input']}")
    print("=" * 50)
    print(f"  Network Address : {info['network_address']}")
    print(f"  Broadcast Addr  : {info['broadcast_address']}")
    print(f"  Subnet Mask     : {info['subnet_mask']}  (/{info['prefix_length']})")
    print(f"  Wildcard Mask   : {info['wildcard_mask']}")
    print(f"  First Host      : {info['first_host']}")
    print(f"  Last Host       : {info['last_host']}")
    print(f"  Usable Hosts    : {info['usable_hosts']:,}")
    print(f"  Total Addresses : {info['total_addresses']:,}")
    print(f"  IP Class        : Class {info['ip_class']}")
    print(f"  Private Range   : {'Yes' if info['is_private'] else 'No'}")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CompTIA Net+ Subnet Calculator")
    parser.add_argument("--cidr", default="192.168.1.0/24", help="CIDR notation e.g. 192.168.1.0/24")
    parser.add_argument("--split", type=int, help="Split into subnets with this prefix length")
    args = parser.parse_args()

    info = calculate_subnet(args.cidr)
    print_subnet_table(info)

    if args.split:
        print(f"Splitting {args.cidr} into /{args.split} subnets:\n")
        subnets = split_subnet(args.cidr, args.split)
        for i, s in enumerate(subnets, 1):
            print(f"  Subnet {i}: {s['network_address']}/{s['prefix_length']}  "
                  f"Hosts: {s['first_host']} - {s['last_host']}  "
                  f"({s['usable_hosts']} usable)")
