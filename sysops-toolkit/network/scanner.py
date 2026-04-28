"""
network/scanner.py
CompTIA Network+ Module — Host Discovery & Network Scanner

Demonstrates: Host discovery, ARP scanning, MAC/OUI lookup, open port
identification, TCP/IP knowledge — Network+ exam objectives.

Requires: nmap installed on the system + python-nmap
"""

import json
import argparse
import datetime

try:
    import nmap
    NMAP_AVAILABLE = True
except (ImportError, Exception):
    NMAP_AVAILABLE = False

# Common OUI vendor prefixes (first 3 octets of MAC address)
OUI_TABLE = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "08:00:27": "VirtualBox",
    "00:1A:2B": "Cisco Systems",
    "00:1B:63": "Apple",
    "AC:DE:48": "Apple",
    "00:16:3E": "Xen (AWS/Cloud)",
    "52:54:00": "QEMU/KVM",
    "00:E0:4C": "Realtek",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "00:14:22": "Dell",
    "18:DB:F2": "Dell",
    "00:1C:7F": "HP",
    "3C:D9:2B": "HP",
    "00:15:5D": "Microsoft (Hyper-V)",
    "00:03:FF": "Microsoft",
    "F0:18:98": "Juniper Networks",
    "00:60:2F": "Cisco-Linksys",
    "CC:FA:00": "Apple",
}


def lookup_vendor(mac: str) -> str:
    """Look up OUI vendor from MAC address."""
    if not mac or mac == "unknown":
        return "Unknown"
    prefix = mac.upper()[:8]
    return OUI_TABLE.get(prefix, "Unknown Vendor")


def scan_network(subnet: str = "192.168.1.0/24") -> dict:
    """
    Scan a subnet for live hosts using Nmap.

    Args:
        subnet: CIDR notation e.g. "192.168.1.0/24"

    Returns:
        dict with scan results including hosts, ports, MACs
    """
    if not NMAP_AVAILABLE:
        return _demo_scan(subnet)

    try:
        nm = nmap.PortScanner()
        print(f"[Net+ Scanner] Scanning {subnet} ...")
        print("[Net+ Scanner] This may take 30-60 seconds...")
        # -sn = ping scan (host discovery only), -O = OS detection (needs root)
        nm.scan(hosts=subnet, arguments="-sn --open")
    except Exception:
        return _demo_scan(subnet)

    hosts = []
    for host in nm.all_hosts():
        info = nm[host]
        mac = info["addresses"].get("mac", "unknown")
        vendor = info.get("vendor", {}).get(mac, lookup_vendor(mac))

        hosts.append({
            "ip": host,
            "hostname": info.hostname() or "unknown",
            "state": info.state(),
            "mac": mac,
            "vendor": vendor,
            "os_guess": "unknown"
        })

    return {
        "subnet": subnet,
        "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hosts_found": len(hosts),
        "hosts": hosts
    }


def _demo_scan(subnet: str) -> dict:
    """
    Demo mode — returns simulated scan results when Nmap is unavailable.
    """
    return {
        "subnet": subnet,
        "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hosts_found": 5,
        "demo_mode": True,
        "hosts": [
            {"ip": "192.168.1.1", "hostname": "router.local", "state": "up",
             "mac": "00:1A:2B:CC:DD:EE", "vendor": "Cisco Systems", "os_guess": "IOS"},
            {"ip": "192.168.1.10", "hostname": "desktop-win11", "state": "up",
             "mac": "00:15:5D:AB:CD:EF", "vendor": "Microsoft (Hyper-V)", "os_guess": "Windows 11"},
            {"ip": "192.168.1.20", "hostname": "macbook-pro", "state": "up",
             "mac": "1B:63:AC:DE:48:FF", "vendor": "Apple", "os_guess": "macOS"},
            {"ip": "192.168.1.30", "hostname": "raspberrypi", "state": "up",
             "mac": "B8:27:EB:12:34:56", "vendor": "Raspberry Pi Foundation", "os_guess": "Linux"},
            {"ip": "192.168.1.50", "hostname": "unknown", "state": "up",
             "mac": "52:54:00:AA:BB:CC", "vendor": "QEMU/KVM", "os_guess": "Linux VM"},
        ]
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CompTIA Net+ Network Scanner")
    parser.add_argument("--subnet", default="192.168.1.0/24", help="Subnet to scan in CIDR notation")
    args = parser.parse_args()

    results = scan_network(args.subnet)

    if "error" in results:
        print(f"[ERROR] {results['error']}")
    else:
        mode = " [DEMO MODE]" if results.get("demo_mode") else ""
        print(f"\n[Net+ Scanner] Results for {results['subnet']}{mode}")
        print(f"Scanned at: {results['scan_time']}")
        print(f"Hosts found: {results['hosts_found']}\n")
        print(f"{'IP':<18} {'Hostname':<25} {'MAC':<20} {'Vendor':<25} {'State'}")
        print("-" * 100)
        for h in results["hosts"]:
            print(f"{h['ip']:<18} {h['hostname']:<25} {h['mac']:<20} {h['vendor']:<25} {h['state']}")