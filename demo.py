"""
Demo - Blockchain Security Incident Logging & Forensics System
Simulates a realistic 72-hour security incident scenario with forensic analysis.
"""

import json
import time
from datetime import datetime
from blockchain import SecurityBlockchain, IncidentRecord
from forensics import ForensicsEngine, ThreatIntelligence


def print_section(title: str):
    print(f"\n{'='*65}")
    print(f"  {title}")
    print('='*65)


def print_json(data: dict, indent: int = 2):
    print(json.dumps(data, indent=indent))


def simulate_incidents(bc: SecurityBlockchain) -> list:
    """Simulate a realistic multi-stage attack campaign."""
    print_section("PHASE 1: Initial Reconnaissance & Probing")

    inc1 = IncidentRecord(
        incident_type="NETWORK_INTRUSION",
        severity="LOW",
        source_ip="172.16.0.50",
        target_system="FIREWALL-01",
        description="Port scan detected from external IP. 65535 ports probed in 4 minutes.",
        evidence={
            "type": "NETWORK_LOG",
            "content": "2024-01-15T08:00:00Z SRC=172.16.0.50 DST=10.0.0.1 PROTO=TCP FLAGS=SYN",
            "tool": "Snort IDS",
            "pcap_hash": "a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6"
        },
        reporter_id="IDS-AGENT-01",
        affected_assets=["FIREWALL-01"]
    )
    bc.log_incident(inc1)
    time.sleep(0.1)

    print_section("PHASE 2: Credential Attack")

    inc2 = IncidentRecord(
        incident_type="UNAUTHORIZED_ACCESS",
        severity="HIGH",
        source_ip="172.16.0.50",
        target_system="AUTH-SERVER-01",
        description="Brute force attack: 8,432 failed login attempts in 15 minutes. Admin account locked.",
        evidence={
            "type": "AUTH_LOG",
            "content": "Failed password for admin from 172.16.0.50 port 22 ssh2 [x8432]",
            "tool": "Fail2Ban + SIEM",
            "log_hash": "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9"
        },
        reporter_id="SIEM-AGENT-02",
        affected_assets=["AUTH-SERVER-01", "LDAP-01"]
    )
    bc.log_incident(inc2)
    time.sleep(0.1)

    print_section("PHASE 3: Malware Deployment")

    inc3 = IncidentRecord(
        incident_type="MALWARE_DETECTED",
        severity="CRITICAL",
        source_ip="10.0.0.200",
        target_system="WORKSTATION-DEV-07",
        description="Ransomware strain 'LockBit 3.0' detected. File encryption in progress. C2 beacon active.",
        evidence={
            "type": "MALWARE_SAMPLE",
            "content": "PE32+ executable, SHA256: e3b0c44298fc1c149afbf4c8996fb924",
            "tool": "CrowdStrike Falcon",
            "yara_rule": "LockBit_3_0",
            "c2_server": "10.0.0.200",
            "sandbox_report": "https://sandbox.internal/report/abc123"
        },
        reporter_id="EDR-AGENT-03",
        affected_assets=["WORKSTATION-DEV-07", "FILE-SERVER-02", "BACKUP-01"]
    )
    bc.log_incident(inc3)
    time.sleep(0.1)

    print_section("PHASE 4: Data Exfiltration Attempt")

    inc4 = IncidentRecord(
        incident_type="DATA_BREACH",
        severity="CRITICAL",
        source_ip="192.168.1.100",
        target_system="DATABASE-PROD-01",
        description="Exfiltration attempt: 47GB of PII data transferred to external C2. Blocked by DLP.",
        evidence={
            "type": "DLP_ALERT",
            "content": "OUTBOUND: 47.3GB to 192.168.1.100:443 — PII classification: SSN, CC, DOB",
            "tool": "Symantec DLP",
            "data_categories": ["PII", "FINANCIAL", "MEDICAL"],
            "records_at_risk": 250000
        },
        reporter_id="DLP-AGENT-04",
        affected_assets=["DATABASE-PROD-01", "USER-DATA-STORE", "CUSTOMER-DB"]
    )
    bc.log_incident(inc4)
    time.sleep(0.1)

    print_section("PHASE 5: Privilege Escalation")

    inc5 = IncidentRecord(
        incident_type="PRIVILEGE_ESCALATION",
        severity="CRITICAL",
        source_ip="10.10.10.15",
        target_system="DOMAIN-CONTROLLER-01",
        description="Pass-the-Hash attack. NTLM hash captured and used to authenticate as Domain Admin.",
        evidence={
            "type": "WINDOWS_EVENT_LOG",
            "content": "EventID 4624 LogonType=3 AccountName=svc_backup Domain=CORP",
            "tool": "Microsoft Sentinel",
            "technique": "T1550.002",  # MITRE ATT&CK
            "mitre_tactic": "Lateral Movement"
        },
        reporter_id="SENTINEL-AGENT-05",
        affected_assets=["DOMAIN-CONTROLLER-01", "ALL-AD-OBJECTS"]
    )
    bc.log_incident(inc5)
    time.sleep(0.1)

    print_section("PHASE 6: Insider Threat Detection")

    inc6 = IncidentRecord(
        incident_type="INSIDER_THREAT",
        severity="HIGH",
        source_ip="192.168.50.30",
        target_system="HR-SYSTEM-01",
        description="Employee accessed 1,200 HR records outside business hours. USB transfer detected.",
        evidence={
            "type": "UEBA_ALERT",
            "content": "User: john.smith@corp.com — Anomaly score: 98.7 — Records accessed: 1200",
            "tool": "Splunk UBA",
            "user_account": "john.smith@corp.com",
            "usb_device_id": "VID_0951&PID_1666",
            "files_copied": 1200
        },
        reporter_id="UEBA-AGENT-06",
        affected_assets=["HR-SYSTEM-01", "EMPLOYEE-RECORDS-DB"]
    )
    bc.log_incident(inc6)
    time.sleep(0.1)

    inc7 = IncidentRecord(
        incident_type="DDoS_ATTACK",
        severity="HIGH",
        source_ip="198.51.100.0",
        target_system="WEB-APP-01",
        description="HTTP flood attack: 2.4M requests/second. CDN mitigation activated.",
        evidence={
            "type": "CDN_LOG",
            "content": "Cloudflare: 2,400,000 req/s from 15,000 unique IPs — Botnet confirmed",
            "tool": "Cloudflare WAF",
            "peak_rps": 2400000,
            "unique_sources": 15000,
            "attack_vector": "HTTP_FLOOD"
        },
        reporter_id="WAF-AGENT-07",
        affected_assets=["WEB-APP-01", "LOAD-BALANCER-01"]
    )
    bc.log_incident(inc7)
    time.sleep(0.1)

    inc8 = IncidentRecord(
        incident_type="ZERO_DAY_EXPLOIT",
        severity="CRITICAL",
        source_ip="203.0.113.42",
        target_system="VPN-GATEWAY-01",
        description="CVE-2024-XXXX: Unauthenticated RCE in VPN gateway. PoC exploit code deployed.",
        evidence={
            "type": "EXPLOIT_ARTIFACT",
            "content": "HTTP POST /api/v1/auth — Buffer overflow payload (712 bytes)",
            "tool": "Palo Alto Cortex XDR",
            "cve": "CVE-2024-XXXX",
            "cvss_score": 10.0,
            "exploit_hash": "f1e2d3c4b5a6978869504132"
        },
        reporter_id="XDR-AGENT-08",
        affected_assets=["VPN-GATEWAY-01", "REMOTE-ACCESS-INFRA"]
    )
    bc.log_incident(inc8)

    return [inc1, inc2, inc3, inc4, inc5, inc6, inc7, inc8]


def run_forensic_analysis(bc: SecurityBlockchain, incidents: list):
    """Run comprehensive forensic analysis on the populated blockchain."""
    engine = ForensicsEngine(bc)

    print_section("BLOCKCHAIN VALIDATION")
    validation = bc.validate_chain()
    print_json(validation)

    print_section("CHAIN SUMMARY")
    summary = bc.get_chain_summary()
    print_json(summary)

    print_section("THREAT ACTOR PROFILING — 172.16.0.50")
    profile = engine.profile_threat_actor("172.16.0.50")
    print_json(profile)

    print_section("ATTACK TIMELINE RECONSTRUCTION")
    timeline = engine.reconstruct_attack_timeline()
    for i, event in enumerate(timeline, 1):
        delta = f" (+{event.get('delta_seconds', 0):.0f}s)" if 'delta_seconds' in event else ""
        print(f"  [{i:02d}] {event['timestamp']}{delta}")
        print(f"       {event['incident_type']:30s} | Score: {event['threat_score']:5.1f} | {event['source_ip']}")

    print_section("ATTACK CORRELATION (60-min window)")
    campaigns = engine.correlate_attacks(time_window_minutes=60)
    for c in campaigns:
        print(f"  Campaign: {c['campaign_id']} | {c['incident_count']} incidents | Max Score: {c['max_threat_score']}")
        print(f"    Types: {', '.join(c['attack_types'])}")
        print(f"    Sources: {', '.join(c['source_ips'])}")

    print_section("ANOMALY DETECTION")
    anomalies = engine.detect_anomalies()
    if anomalies:
        for a in anomalies:
            print(f"  [{a['severity']}] {a['type']}: {a['detail']}")
    else:
        print("  No anomalies detected.")

    print_section("SPECIFIC INCIDENT LOOKUP")
    record_id = incidents[2].record_id  # Ransomware incident
    result = bc.get_incident(record_id)
    print(f"  Looking up Ransomware incident: {record_id}")
    if result:
        print(f"  Found in Block #{result['block_index']} | Block Hash: {result['block_hash'][:20]}...")
        print(f"  Type: {result['incident']['incident_type']} | Severity: {result['incident']['severity']}")
        print(f"  Immutable: {result['immutable']}")

    print_section("IP REPUTATION CHECK")
    for ip in ["192.168.1.100", "10.0.0.200", "172.16.0.50", "8.8.8.8"]:
        rep = ThreatIntelligence.check_ip_reputation(ip)
        status = "⚠️  MALICIOUS" if rep["malicious"] else "✅  CLEAN"
        print(f"  {ip:20s} {status}  {rep.get('threat_type', '')}")

    print_section("RISK DASHBOARD")
    dashboard = engine.generate_risk_dashboard()
    print_json({k: v for k, v in dashboard.items() if k != "chain_summary"})

    print_section("EXPORTING FORENSIC REPORT")
    bc.export_forensic_report("forensic_report.json")

    print_section("TAMPER DETECTION DEMO")
    print("  Simulating tampering: modifying block #1 description...")
    if len(bc.chain) > 1:
        original_hash = bc.chain[1].hash
        bc.chain[1].incident_dicts[0]["description"] = "TAMPERED: evidence deleted"
        bc.chain[1].hash = "deadbeef" * 8  # Corrupt the hash

        post_validation = bc.validate_chain()
        print(f"  Original Hash: {original_hash[:25]}...")
        print(f"  Chain Valid After Tampering: {post_validation['valid']}")
        if post_validation["issues"]:
            for issue in post_validation["issues"]:
                print(f"  ❌ {issue}")

        # Restore
        bc.chain[1].hash = original_hash
        bc.chain[1].incident_dicts[0]["description"] = incidents[0].description
        print(f"  Chain Valid After Restore: {bc.validate_chain()['valid']}")


def main():
    print("\n" + "="*65)
    print("   BLOCKCHAIN SECURITY INCIDENT LOGGING & FORENSICS SYSTEM")
    print("   Version 1.0 — Digital Forensics & Incident Response")
    print("="*65)

    # Initialize blockchain with PoW difficulty=3 and max 10 incidents per block
    bc = SecurityBlockchain(difficulty=3, max_block_size=10)

    # Simulate incidents
    incidents = simulate_incidents(bc)

    # Mine remaining pending incidents
    print_section("MINING PENDING INCIDENTS")
    bc.mine_pending_incidents(miner_id="MINER-NODE-01")

    # Run forensic analysis
    run_forensic_analysis(bc, incidents)

    print("\n" + "="*65)
    print("  ANALYSIS COMPLETE")
    print("="*65 + "\n")


if __name__ == "__main__":
    main()
