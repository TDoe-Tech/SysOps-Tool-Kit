"""
hardware/diagnostics.py
CompTIA A+ Module — Hardware Diagnostics Collector

Demonstrates: Hardware monitoring, troubleshooting methodology,
OS-level system information retrieval (A+ Core 1 & 2 objectives).
"""

import psutil
import platform
import datetime
import json


def get_cpu_info():
    """Collect CPU usage and frequency data."""
    freq = psutil.cpu_freq()
    return {
        "usage_percent": psutil.cpu_percent(interval=1),
        "core_count_physical": psutil.cpu_count(logical=False),
        "core_count_logical": psutil.cpu_count(logical=True),
        "freq_current_mhz": round(freq.current, 1) if freq else None,
        "freq_max_mhz": round(freq.max, 1) if freq else None,
        "status": "OK"
    }


def get_ram_info():
    """Collect RAM usage statistics."""
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        "total_gb": round(mem.total / (1024 ** 3), 2),
        "available_gb": round(mem.available / (1024 ** 3), 2),
        "used_gb": round(mem.used / (1024 ** 3), 2),
        "usage_percent": mem.percent,
        "swap_total_gb": round(swap.total / (1024 ** 3), 2),
        "swap_used_gb": round(swap.used / (1024 ** 3), 2),
        "status": "WARNING" if mem.percent > 85 else "OK"
    }


def get_disk_info():
    """Collect disk usage for all mounted partitions."""
    disks = []
    for partition in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            status = "CRITICAL" if usage.percent > 90 else "WARNING" if usage.percent > 75 else "OK"
            disks.append({
                "device": partition.device,
                "mountpoint": partition.mountpoint,
                "fstype": partition.fstype,
                "total_gb": round(usage.total / (1024 ** 3), 2),
                "used_gb": round(usage.used / (1024 ** 3), 2),
                "free_gb": round(usage.free / (1024 ** 3), 2),
                "usage_percent": usage.percent,
                "status": status,
                "smart_note": "S.M.A.R.T. check requires elevated privileges (run as admin/root)"
            })
        except PermissionError:
            continue
    return disks


def get_temperature_info():
    """Collect CPU temperature sensors if available."""
    try:
        temps = psutil.sensors_temperatures()
        if not temps:
            return {"available": False, "note": "Temperature sensors not available on this platform"}
        results = {}
        for name, entries in temps.items():
            results[name] = [
                {
                    "label": e.label or "sensor",
                    "current_c": e.current,
                    "high_c": e.high,
                    "critical_c": e.critical,
                    "status": "CRITICAL" if (e.critical and e.current >= e.critical)
                              else "WARNING" if (e.high and e.current >= e.high)
                              else "OK"
                }
                for e in entries
            ]
        return {"available": True, "sensors": results}
    except AttributeError:
        return {"available": False, "note": "Temperature sensors not supported on this OS"}


def get_system_info():
    """Collect basic OS and platform info."""
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.datetime.now() - boot_time
    return {
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "hostname": platform.node(),
        "boot_time": boot_time.strftime("%Y-%m-%d %H:%M:%S"),
        "uptime_hours": round(uptime.total_seconds() / 3600, 1)
    }


def run_diagnostics():
    """Run full hardware diagnostic scan and return results dict."""
    print("[A+ Diagnostics] Running hardware check...")
    results = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "system": get_system_info(),
        "cpu": get_cpu_info(),
        "ram": get_ram_info(),
        "disks": get_disk_info(),
        "temperature": get_temperature_info()
    }

    # Overall health determination
    statuses = [results["cpu"]["status"], results["ram"]["status"]]
    statuses += [d["status"] for d in results["disks"]]
    if "CRITICAL" in statuses:
        results["overall_health"] = "CRITICAL"
    elif "WARNING" in statuses:
        results["overall_health"] = "WARNING"
    else:
        results["overall_health"] = "HEALTHY"

    return results


if __name__ == "__main__":
    data = run_diagnostics()
    print(json.dumps(data, indent=2))
    print(f"\n[Overall Health]: {data['overall_health']}")
