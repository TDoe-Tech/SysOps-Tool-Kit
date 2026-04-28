"""
security/ingest.py
CompTIA Security+ Module — Log Ingestion & Normalization

Demonstrates: Log analysis, Windows Event ID knowledge, security monitoring,
data normalization for SIEM-style processing Security+ objectives.
"""

import json
import argparse
import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


# Windows Security Event ID reference (key Security+ knowledge)
EVENT_ID_MAP = {
    4624: {"name": "Successful Logon", "category": "authentication", "severity": "info"},
    4625: {"name": "Failed Logon", "category": "authentication", "severity": "warning"},
    4634: {"name": "Account Logoff", "category": "authentication", "severity": "info"},
    4648: {"name": "Logon with Explicit Credentials", "category": "authentication", "severity": "warning"},
    4672: {"name": "Special Privileges Assigned", "category": "privilege", "severity": "warning"},
    4698: {"name": "Scheduled Task Created", "category": "persistence", "severity": "high"},
    4720: {"name": "User Account Created", "category": "account_management", "severity": "warning"},
    4722: {"name": "User Account Enabled", "category": "account_management", "severity": "info"},
    4723: {"name": "Password Change Attempt", "category": "account_management", "severity": "warning"},
    4726: {"name": "User Account Deleted", "category": "account_management", "severity": "warning"},
    4740: {"name": "Account Lockout", "category": "authentication", "severity": "high"},
    4756: {"name": "Member Added to Security Group", "category": "account_management", "severity": "warning"},
    1102: {"name": "Audit Log Cleared", "category": "defense_evasion", "severity": "critical"},
    7045: {"name": "New Service Installed", "category": "persistence", "severity": "high"},
}

LOGON_TYPES = {
    2: "Interactive (local keyboard)",
    3: "Network (SMB, RDP without NLA)",
    4: "Batch (scheduled task)",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext (plaintext password)",
    9: "NewCredentials (RunAs)",
    10: "RemoteInteractive (RDP with NLA)",
    11: "CachedInteractive (offline domain logon)"
}


def load_logs(log_path: str) -> list:
    """Load and parse a JSON log file."""
    path = Path(log_path)
    if not path.is_absolute():
        path = BASE_DIR / path
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    with open(path) as f:
        raw = json.load(f)

    if not isinstance(raw, list):
        raise ValueError("Log file must contain a JSON array of events")

    return raw


def normalize_event(raw_event: dict) -> dict:
    """
    Normalize a raw Windows event log entry into a standard format.

    Returns a structured event dict with enriched metadata.
    """
    event_id = raw_event.get("EventID")
    meta = EVENT_ID_MAP.get(event_id, {
        "name": "Unknown Event",
        "category": "unknown",
        "severity": "info"
    })

    logon_type = raw_event.get("LogonType")
    logon_type_desc = LOGON_TYPES.get(logon_type, "N/A") if logon_type else "N/A"

    return {
        "event_id": event_id,
        "event_name": meta["name"],
        "category": meta["category"],
        "severity": meta["severity"],
        "timestamp": raw_event.get("TimeCreated", "unknown"),
        "computer": raw_event.get("Computer", "unknown"),
        "source_user": raw_event.get("SubjectUserName", "N/A"),
        "target_user": raw_event.get("TargetUserName", "N/A"),
        "source_ip": raw_event.get("IpAddress", "N/A"),
        "logon_type": logon_type_desc,
        "message": raw_event.get("Message", ""),
        "raw": raw_event
    }


def ingest(log_path: str) -> list:
    """
    Full ingestion pipeline: load → normalize → return event list.

    Args:
        log_path: Path to JSON log file

    Returns:
        List of normalized event dicts
    """
    raw_events = load_logs(log_path)
    normalized = [normalize_event(e) for e in raw_events]
    print(f"[Sec+ Ingest] Loaded {len(normalized)} events from {log_path}")
    return normalized


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CompTIA Sec+ Log Ingestor")
    parser.add_argument("--log", default="sample_logs/windows_events.json")
    args = parser.parse_args()

    events = ingest(args.log)
    print(f"\n{'Event ID':<10} {'Severity':<10} {'Category':<22} {'Computer':<18} {'User':<15} {'Timestamp'}")
    print("-" * 100)
    for e in events:
        print(f"{e['event_id']:<10} {e['severity']:<10} {e['category']:<22} {e['computer']:<18} {e['target_user']:<15} {e['timestamp']}")
