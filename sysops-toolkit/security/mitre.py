"""
security/mitre.py
CompTIA Security+ Module — MITRE ATT&CK Reference

Provides technique lookups and tactic context for detected threats.
Demonstrates understanding of the MITRE ATT&CK framework — a key
Security+ domain (Threats, Attacks and Vulnerabilities).
"""

TECHNIQUES = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
        "mitigations": [
            "Multi-factor authentication (MFA)",
            "Account lockout policies",
            "Password complexity requirements",
            "Monitor for repeated authentication failures (Event 4625)"
        ]
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
        "description": "Adversaries with no prior knowledge of legitimate credentials may guess passwords to attempt access.",
        "mitigations": [
            "Enable account lockout after N failed attempts",
            "Use strong password policies",
            "Monitor Event ID 4625 for repeated failures from same source"
        ]
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1068/",
        "description": "Adversaries may exploit software vulnerabilities to elevate privileges.",
        "mitigations": [
            "Keep systems patched and up to date",
            "Use least privilege principles",
            "Monitor Event ID 4672 for sensitive privilege assignments",
            "Deploy endpoint detection and response (EDR) tools"
        ]
    },
    "T1070.001": {
        "name": "Indicator Removal: Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1070/001/",
        "description": "Adversaries may clear Windows Event Logs to remove evidence of intrusion.",
        "mitigations": [
            "Forward logs to a remote SIEM in real-time",
            "Restrict log clearing permissions",
            "Alert on Event ID 1102 (audit log cleared)"
        ]
    },
    "T1053.005": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence, Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1053/005/",
        "description": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code.",
        "mitigations": [
            "Monitor Event ID 4698 for new scheduled task creation",
            "Audit scheduled tasks regularly",
            "Restrict task creation to privileged users"
        ]
    }
}


def lookup(technique_id: str) -> dict:
    """Look up a MITRE ATT&CK technique by ID."""
    return TECHNIQUES.get(technique_id, {
        "name": "Unknown Technique",
        "tactic": "Unknown",
        "url": f"https://attack.mitre.org/techniques/{technique_id}/",
        "description": "Technique details not in local database.",
        "mitigations": []
    })


def print_technique(technique_id: str):
    """Pretty print a technique lookup."""
    t = lookup(technique_id)
    print(f"\n{'='*55}")
    print(f"  MITRE ATT&CK: {technique_id} — {t['name']}")
    print(f"{'='*55}")
    print(f"  Tactic       : {t['tactic']}")
    print(f"  Reference    : {t['url']}")
    print(f"\n  Description  : {t['description']}")
    print(f"\n  Mitigations:")
    for m in t['mitigations']:
        print(f"    • {m}")
    print()


if __name__ == "__main__":
    for tid in TECHNIQUES:
        print_technique(tid)
