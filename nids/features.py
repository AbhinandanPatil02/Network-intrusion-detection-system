"""Feature metadata for the 39 CIC-IDS2017-style flow features the models expect.

The order here MUST match the order returned by ``flow.Flow.terminated()`` and
the order the Random Forest / autoencoder were trained on.
"""

FEATURES = [
    ("FlowDuration", "Flow duration (µs)"),
    ("BwdPacketLenMax", "Bwd packet length max"),
    ("BwdPacketLenMin", "Bwd packet length min"),
    ("BwdPacketLenMean", "Bwd packet length mean"),
    ("BwdPacketLenStd", "Bwd packet length std"),
    ("FlowIATMean", "Flow IAT mean"),
    ("FlowIATStd", "Flow IAT std"),
    ("FlowIATMax", "Flow IAT max"),
    ("FlowIATMin", "Flow IAT min"),
    ("FwdIATTotal", "Fwd IAT total"),
    ("FwdIATMean", "Fwd IAT mean"),
    ("FwdIATStd", "Fwd IAT std"),
    ("FwdIATMax", "Fwd IAT max"),
    ("FwdIATMin", "Fwd IAT min"),
    ("BwdIATTotal", "Bwd IAT total"),
    ("BwdIATMean", "Bwd IAT mean"),
    ("BwdIATStd", "Bwd IAT std"),
    ("BwdIATMax", "Bwd IAT max"),
    ("BwdIATMin", "Bwd IAT min"),
    ("FwdPSHFlags", "Fwd PSH flags"),
    ("FwdPackets_s", "Fwd packets / s"),
    ("MaxPacketLen", "Packet length max"),
    ("PacketLenMean", "Packet length mean"),
    ("PacketLenStd", "Packet length std"),
    ("PacketLenVar", "Packet length variance"),
    ("FINFlagCount", "FIN flag"),
    ("SYNFlagCount", "SYN flag"),
    ("PSHFlagCount", "PSH flag"),
    ("ACKFlagCount", "ACK flag"),
    ("URGFlagCount", "URG flag"),
    ("AvgPacketSize", "Average packet size"),
    ("AvgBwdSegmentSize", "Avg bwd segment size"),
    ("InitWinBytesFwd", "Init window bytes fwd"),
    ("InitWinBytesBwd", "Init window bytes bwd"),
    ("ActiveMin", "Active min"),
    ("IdleMean", "Idle mean"),
    ("IdleStd", "Idle std"),
    ("IdleMax", "Idle max"),
    ("IdleMin", "Idle min"),
]

FEATURE_KEYS = [k for k, _ in FEATURES]
FEATURE_LABELS = [lbl for _, lbl in FEATURES]
N_FEATURES = len(FEATURES)

# MITRE ATT&CK mapping + analyst guidance for each class the model emits.
THREAT_INTEL = {
    "Benign": {
        "tactic": "—", "technique": "—",
        "description": "Traffic consistent with normal behaviour.",
        "recommendation": "No action required.",
    },
    "Botnet": {
        "tactic": "Command and Control", "technique": "T1071 Application Layer Protocol",
        "description": "Periodic beaconing typical of a compromised host talking to C2 infrastructure.",
        "recommendation": "Isolate the internal host, inspect running processes and persistence, block the remote endpoint.",
    },
    "DDoS": {
        "tactic": "Impact", "technique": "T1498 Network Denial of Service",
        "description": "High-rate traffic from many sources intended to exhaust a service.",
        "recommendation": "Engage upstream scrubbing / rate limiting, verify service health, capture samples for the ISP.",
    },
    "DoS": {
        "tactic": "Impact", "technique": "T1499 Endpoint Denial of Service",
        "description": "Resource-exhaustion pattern (e.g. slowloris, Hulk, GoldenEye) against a single service.",
        "recommendation": "Rate-limit or block the source, tune server connection timeouts.",
    },
    "FTP-Patator": {
        "tactic": "Credential Access", "technique": "T1110 Brute Force",
        "description": "Repeated FTP authentication attempts — credential brute forcing.",
        "recommendation": "Block the source, enforce account lockout, disable plaintext FTP where possible.",
    },
    "SSH-Patator": {
        "tactic": "Credential Access", "technique": "T1110 Brute Force",
        "description": "Repeated SSH authentication attempts — credential brute forcing.",
        "recommendation": "Block the source, require key-based auth, deploy fail2ban or equivalent.",
    },
    "Probe": {
        "tactic": "Discovery", "technique": "T1046 Network Service Discovery",
        "description": "Port or service scanning to map exposed services.",
        "recommendation": "Verify only intended services are exposed; block or monitor the scanning source.",
    },
    "Web Attack": {
        "tactic": "Initial Access", "technique": "T1190 Exploit Public-Facing Application",
        "description": "Web exploitation pattern (brute force, XSS, SQL injection).",
        "recommendation": "Review web server / WAF logs for the session, patch the application, block the source.",
    },
    "Anomaly": {
        "tactic": "Unknown", "technique": "—",
        "description": "Flow deviates strongly from the learned baseline of normal traffic (autoencoder). "
                       "May indicate a novel attack or an unusual-but-legitimate application.",
        "recommendation": "Triage manually: check the process, destination reputation and payload if available.",
    },
}

WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 1900: "SSDP",
    3306: "MySQL", 3389: "RDP", 5060: "SIP", 5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elasticsearch", 27017: "MongoDB",
}
