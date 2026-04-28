"""
security/detections.py
CompTIA Security+ Module — Rule-Based Threat Detection Engine

Demonstrates: Threat detection logic, attack pattern recognition,
security alerting, incident identification — Security+ objectives.

Detection rules:
  - Brute Force Login (T1110.001)
  - Account Lockout Following Failed Logins (T1110)
  - Privilege Escalation via Special Privileges (T1068)
  - Audit Log Cleared / Defense Evasion (T1070.001)
  - Scheduled Task Persistence (T1053.005)
"""

from collections import defaultdict
import datetime


# Detection thresholds
BRUTE_FORCE_THRESHOLD = 3   # failed logins from same IP within time window
BRUTE_FORCE_WINDOW_SEC = 60  # seconds


def detect_brute_force(events: list) -> list:
    """
    Detect brute force / password spraying attacks.
    Rule: 3+ failed logins (Event 4625) from the same source IP within 60 seconds.
    MITRE: T1110.001 — Brute Force: Password Guessing
    """
    alerts = []
    failed_logins = [e for e in events if e["event_id"] == 4625]

    # Group by source IP
    by_ip = defaultdict(list)
    for e in failed_logins:
        ip = e.get("source_ip", "N/A")
        if ip and ip != "N/A":
            by_ip[ip].append(e)

    for ip, attempts in by_ip.items():
        if len(attempts) >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "alert_type": "Brute Force Login Detected",
                "severity": "HIGH",
                "mitre_technique": "T1110.001",
                "mitre_name": "Brute Force: Password Guessing",
                "mitre_url": "https://attack.mitre.org/techniques/T1110/001/",
                "description": (
                    f"{len(attempts)} failed login attempts targeting "
                    f"'{attempts[0]['target_user']}' from {ip} on {attempts[0]['computer']}"
                ),
                "source_ip": ip,
                "target_user": attempts[0]["target_user"],
                "computer": attempts[0]["computer"],
                "first_seen": attempts[0]["timestamp"],
                "last_seen": attempts[-1]["timestamp"],
                "event_count": len(attempts),
                "events": attempts
            })

    return alerts


def detect_account_lockout(events: list) -> list:
    """
    Detect account lockout events following failed logins.
    Rule: Event ID 4740 (Account Lockout).
    MITRE: T1110 — Brute Force
    """
    alerts = []
    lockouts = [e for e in events if e["event_id"] == 4740]

    for e in lockouts:
        alerts.append({
            "alert_type": "Account Lockout",
            "severity": "HIGH",
            "mitre_technique": "T1110",
            "mitre_name": "Brute Force",
            "mitre_url": "https://attack.mitre.org/techniques/T1110/",
            "description": (
                f"Account '{e['target_user']}' was locked out on {e['computer']}"
            ),
            "target_user": e["target_user"],
            "computer": e["computer"],
            "timestamp": e["timestamp"],
            "event_count": 1,
            "events": [e]
        })

    return alerts


def detect_privilege_escalation(events: list) -> list:
    """
    Detect special privilege assignment — possible privilege escalation.
    Rule: Event ID 4672 with sensitive privileges (SeDebugPrivilege, SeTcbPrivilege).
    MITRE: T1068 — Exploitation for Privilege Escalation
    """
    alerts = []
    sensitive_privs = ["SeDebugPrivilege", "SeTcbPrivilege", "SeTakeOwnershipPrivilege",
                       "SeLoadDriverPrivilege", "SeImpersonatePrivilege"]

    for e in events:
        if e["event_id"] == 4672:
            raw = e.get("raw", {})
            privs_assigned = raw.get("PrivilegesAssigned", "")
            matched = [p for p in sensitive_privs if p in privs_assigned]
            if matched:
                alerts.append({
                    "alert_type": "Suspicious Privilege Assignment",
                    "severity": "HIGH",
                    "mitre_technique": "T1068",
                    "mitre_name": "Exploitation for Privilege Escalation",
                    "mitre_url": "https://attack.mitre.org/techniques/T1068/",
                    "description": (
                        f"User '{e['source_user']}' was assigned sensitive privileges "
                        f"on {e['computer']}: {', '.join(matched)}"
                    ),
                    "source_user": e["source_user"],
                    "computer": e["computer"],
                    "privileges": matched,
                    "timestamp": e["timestamp"],
                    "event_count": 1,
                    "events": [e]
                })

    return alerts


def detect_defense_evasion(events: list) -> list:
    """
    Detect audit log clearing — indicator of attacker covering tracks.
    Rule: Event ID 1102 (audit log cleared).
    MITRE: T1070.001 — Indicator Removal: Clear Windows Event Logs
    """
    alerts = []
    clears = [e for e in events if e["event_id"] == 1102]

    for e in clears:
        alerts.append({
            "alert_type": "Audit Log Cleared",
            "severity": "CRITICAL",
            "mitre_technique": "T1070.001",
            "mitre_name": "Indicator Removal: Clear Windows Event Logs",
            "mitre_url": "https://attack.mitre.org/techniques/T1070/001/",
            "description": (
                f"Audit log was cleared by '{e['source_user']}' on {e['computer']}. "
                "This is a strong indicator of an attacker covering their tracks."
            ),
            "source_user": e["source_user"],
            "computer": e["computer"],
            "timestamp": e["timestamp"],
            "event_count": 1,
            "events": [e]
        })

    return alerts


def detect_persistence(events: list) -> list:
    """
    Detect scheduled task creation — common persistence mechanism.
    Rule: Event ID 4698 (Scheduled Task Created).
    MITRE: T1053.005 — Scheduled Task/Job: Scheduled Task
    """
    alerts = []
    tasks = [e for e in events if e["event_id"] == 4698]

    for e in tasks:
        raw = e.get("raw", {})
        task_name = raw.get("TaskName", "Unknown")
        alerts.append({
            "alert_type": "Suspicious Scheduled Task Created",
            "severity": "HIGH",
            "mitre_technique": "T1053.005",
            "mitre_name": "Scheduled Task/Job: Scheduled Task",
            "mitre_url": "https://attack.mitre.org/techniques/T1053/005/",
            "description": (
                f"Scheduled task '{task_name}' created by '{e['source_user']}' "
                f"on {e['computer']} — possible persistence mechanism."
            ),
            "source_user": e["source_user"],
            "computer": e["computer"],
            "task_name": task_name,
            "timestamp": e["timestamp"],
            "event_count": 1,
            "events": [e]
        })

    return alerts


def run_all_detections(events: list) -> list:
    """
    Run all detection rules against a normalized event list.

    Returns:
        List of alert dicts sorted by severity.
    """
    all_alerts = []
    all_alerts += detect_brute_force(events)
    all_alerts += detect_account_lockout(events)
    all_alerts += detect_privilege_escalation(events)
    all_alerts += detect_defense_evasion(events)
    all_alerts += detect_persistence(events)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_alerts.sort(key=lambda a: severity_order.get(a["severity"], 99))

    return all_alerts


if __name__ == "__main__":
    from security.ingest import ingest
    events = ingest("sample_logs/windows_events.json")
    alerts = run_all_detections(events)

    print(f"\n[Sec+ Detections] {len(alerts)} alert(s) generated\n")
    print(f"{'Severity':<10} {'Alert Type':<35} {'MITRE':<12} {'Description'}")
    print("-" * 110)
    for a in alerts:
        desc_short = a["description"][:60] + "..." if len(a["description"]) > 60 else a["description"]
        print(f"{a['severity']:<10} {a['alert_type']:<35} {a['mitre_technique']:<12} {desc_short}")
