"""
SentinelMind - MITRE ATT&CK Mapper
Maps detected event types to MITRE ATT&CK tactics and techniques
"""

# MITRE ATT&CK mapping: event_type -> tactic + technique
MITRE_MAP = {
    "failed_login": {
        "tactic": "Credential Access",
        "technique": "T1110 - Brute Force",
        "description": "Adversary attempting to gain access by guessing credentials repeatedly.",
        "mitigation": "Enforce account lockout policies and enable MFA.",
    },
    "port_scan": {
        "tactic": "Reconnaissance",
        "technique": "T1046 - Network Service Scanning",
        "description": "Adversary scanning open ports to identify services for exploitation.",
        "mitigation": "Enable network intrusion detection; block scanning IPs at firewall.",
    },
    "suspicious_process": {
        "tactic": "Execution",
        "technique": "T1059 - Command and Scripting Interpreter",
        "description": "Adversary using shell commands or scripts to execute malicious code.",
        "mitigation": "Apply application allowlisting; monitor process creation events.",
    },
    "data_exfiltration": {
        "tactic": "Exfiltration",
        "technique": "T1048 - Exfiltration Over Alternative Protocol",
        "description": "Adversary transferring data to external destination to steal sensitive info.",
        "mitigation": "Monitor outbound traffic; set data loss prevention (DLP) policies.",
    },
    "privilege_escalation": {
        "tactic": "Privilege Escalation",
        "technique": "T1548 - Abuse Elevation Control Mechanism",
        "description": "Adversary attempting to gain higher-level permissions on the system.",
        "mitigation": "Restrict sudo usage; audit privilege escalation commands.",
    },
}

DEFAULT_MITRE = {
    "tactic": "Unknown",
    "technique": "T0000 - Unclassified",
    "description": "Event does not match known MITRE ATT&CK patterns.",
    "mitigation": "Manual investigation required.",
}


def get_mitre_info(event_type: str) -> dict:
    """Returns MITRE ATT&CK info for a given event type."""
    return MITRE_MAP.get(event_type, DEFAULT_MITRE)