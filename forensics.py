"""
Forensics Engine - Advanced analysis and threat intelligence for the Security Blockchain.
Provides threat correlation, IP reputation analysis, timeline reconstruction,
and automated threat scoring.
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from collections import defaultdict
from blockchain import SecurityBlockchain, IncidentRecord


class ThreatIntelligence:
    """Maintains known threat indicators and scoring logic."""

    KNOWN_MALICIOUS_IPS = {
        "192.168.1.100": {"threat_type": "C2_SERVER", "confidence": 0.95},
        "10.0.0.200":    {"threat_type": "BOTNET_NODE", "confidence": 0.88},
        "172.16.0.50":   {"threat_type": "SCANNER",    "confidence": 0.75},
    }

    SEVERITY_SCORES = {"LOW": 1, "MEDIUM": 3, "HIGH": 7, "CRITICAL": 10}

    INCIDENT_WEIGHTS = {
        "RANSOMWARE": 10, "ZERO_DAY_EXPLOIT": 10, "DATA_BREACH": 9,
        "PRIVILEGE_ESCALATION": 8, "INSIDER_THREAT": 8, "NETWORK_INTRUSION": 7,
        "MALWARE_DETECTED": 7, "DDoS_ATTACK": 6, "UNAUTHORIZED_ACCESS": 5,
        "PHISHING": 4, "OTHER": 2
    }

    @classmethod
    def check_ip_reputation(cls, ip: str) -> dict:
        if ip in cls.KNOWN_MALICIOUS_IPS:
            info = cls.KNOWN_MALICIOUS_IPS[ip]
            return {"ip": ip, "malicious": True, **info}
        return {"ip": ip, "malicious": False, "threat_type": None, "confidence": 0.0}

    @classmethod
    def score_incident(cls, incident: dict) -> float:
        sev_score = cls.SEVERITY_SCORES.get(incident.get("severity", "LOW"), 1)
        type_weight = cls.INCIDENT_WEIGHTS.get(incident.get("incident_type", "OTHER"), 2)
        ip_rep = cls.check_ip_reputation(incident.get("source_ip", ""))
        ip_bonus = 3.0 if ip_rep["malicious"] else 0.0
        return round(sev_score * type_weight * 0.5 + ip_bonus, 2)


class ForensicsEngine:
    """
    Advanced forensics and threat analysis engine built on top of the SecurityBlockchain.
    Provides: attack correlation, threat actor profiling, timeline reconstruction,
    anomaly detection, and risk scoring.
    """

    def __init__(self, blockchain: SecurityBlockchain):
        self.bc = blockchain
        self.ti = ThreatIntelligence()

    # ─── Timeline Reconstruction ────────────────────────────────────────────────

    def reconstruct_attack_timeline(self, source_ip: str = None,
                                    target_system: str = None) -> List[dict]:
        """Reconstruct a chronological attack timeline filtered by source IP or target."""
        events = []
        for block in self.bc.chain[1:]:
            for inc in block.incident_dicts:
                match = True
                if source_ip and inc["source_ip"] != source_ip:
                    match = False
                if target_system and inc["target_system"] != target_system:
                    match = False
                if match:
                    events.append({
                        "timestamp": inc["timestamp"],
                        "incident_type": inc["incident_type"],
                        "severity": inc["severity"],
                        "source_ip": inc["source_ip"],
                        "target_system": inc["target_system"],
                        "description": inc["description"],
                        "threat_score": self.ti.score_incident(inc),
                        "block_index": block.index
                    })

        events.sort(key=lambda x: x["timestamp"])

        # Annotate with time deltas
        for i in range(1, len(events)):
            t1 = datetime.fromisoformat(events[i - 1]["timestamp"].replace("Z", ""))
            t2 = datetime.fromisoformat(events[i]["timestamp"].replace("Z", ""))
            events[i]["delta_seconds"] = (t2 - t1).total_seconds()

        return events

    # ─── Threat Actor Profiling ─────────────────────────────────────────────────

    def profile_threat_actor(self, source_ip: str) -> dict:
        """Build a comprehensive profile of a threat actor based on observed incidents."""
        incidents = self.bc.query_incidents(source_ip=source_ip)
        if not incidents:
            return {"source_ip": source_ip, "incidents_found": 0}

        severity_dist: Dict[str, int] = defaultdict(int)
        type_dist: Dict[str, int] = defaultdict(int)
        targeted_systems = set()
        affected_assets = set()
        total_score = 0.0

        for inc in incidents:
            severity_dist[inc["severity"]] += 1
            type_dist[inc["incident_type"]] += 1
            targeted_systems.add(inc["target_system"])
            affected_assets.update(inc.get("affected_assets", []))
            total_score += self.ti.score_incident(inc)

        ip_rep = self.ti.check_ip_reputation(source_ip)
        sophistication = self._estimate_sophistication(list(type_dist.keys()))

        return {
            "source_ip": source_ip,
            "ip_reputation": ip_rep,
            "total_incidents": len(incidents),
            "cumulative_threat_score": round(total_score, 2),
            "severity_distribution": dict(severity_dist),
            "attack_type_distribution": dict(type_dist),
            "targeted_systems": list(targeted_systems),
            "affected_assets": list(affected_assets),
            "sophistication_level": sophistication,
            "first_seen": min(inc["timestamp"] for inc in incidents),
            "last_seen": max(inc["timestamp"] for inc in incidents),
            "persistence": len(set(inc["timestamp"][:10] for inc in incidents))  # active days
        }

    def _estimate_sophistication(self, attack_types: List[str]) -> str:
        high_soph = {"ZERO_DAY_EXPLOIT", "RANSOMWARE", "INSIDER_THREAT", "PRIVILEGE_ESCALATION"}
        med_soph = {"NETWORK_INTRUSION", "MALWARE_DETECTED", "DATA_BREACH"}
        if any(t in high_soph for t in attack_types):
            return "ADVANCED PERSISTENT THREAT (APT)"
        if any(t in med_soph for t in attack_types):
            return "INTERMEDIATE"
        return "OPPORTUNISTIC"

    # ─── Attack Correlation ─────────────────────────────────────────────────────

    def correlate_attacks(self, time_window_minutes: int = 60) -> List[dict]:
        """Detect coordinated attack campaigns within a sliding time window."""
        all_incidents = []
        for block in self.bc.chain[1:]:
            for inc in block.incident_dicts:
                all_incidents.append(inc)
        all_incidents.sort(key=lambda x: x["timestamp"])

        campaigns = []
        visited = set()

        for i, anchor in enumerate(all_incidents):
            if anchor["record_id"] in visited:
                continue
            anchor_time = datetime.fromisoformat(anchor["timestamp"].replace("Z", ""))
            group = [anchor]
            visited.add(anchor["record_id"])

            for j in range(i + 1, len(all_incidents)):
                candidate = all_incidents[j]
                if candidate["record_id"] in visited:
                    continue
                cand_time = datetime.fromisoformat(candidate["timestamp"].replace("Z", ""))
                if (cand_time - anchor_time).total_seconds() > time_window_minutes * 60:
                    break
                # Correlate by same source IP OR same target OR related types
                if (candidate["source_ip"] == anchor["source_ip"] or
                        candidate["target_system"] == anchor["target_system"]):
                    group.append(candidate)
                    visited.add(candidate["record_id"])

            if len(group) > 1:
                max_score = max(self.ti.score_incident(inc) for inc in group)
                campaigns.append({
                    "campaign_id": f"CAMP-{len(campaigns)+1:04d}",
                    "incident_count": len(group),
                    "time_span_minutes": time_window_minutes,
                    "max_threat_score": max_score,
                    "severity_max": max(
                        (inc["severity"] for inc in group),
                        key=lambda s: ThreatIntelligence.SEVERITY_SCORES.get(s, 0)),
                    "attack_types": list(set(inc["incident_type"] for inc in group)),
                    "source_ips": list(set(inc["source_ip"] for inc in group)),
                    "target_systems": list(set(inc["target_system"] for inc in group)),
                    "start_time": group[0]["timestamp"],
                    "incidents": [inc["record_id"] for inc in group]
                })

        return campaigns

    # ─── Anomaly Detection ──────────────────────────────────────────────────────

    def detect_anomalies(self) -> List[dict]:
        """Detect statistical anomalies in the incident logs."""
        anomalies = []
        ip_counts: Dict[str, int] = defaultdict(int)
        system_counts: Dict[str, int] = defaultdict(int)
        hourly_counts: Dict[str, int] = defaultdict(int)

        for block in self.bc.chain[1:]:
            for inc in block.incident_dicts:
                ip_counts[inc["source_ip"]] += 1
                system_counts[inc["target_system"]] += 1
                hour = inc["timestamp"][:13]  # YYYY-MM-DDTHH
                hourly_counts[hour] += 1

        # Flag IPs with high frequency
        avg_ip = sum(ip_counts.values()) / max(len(ip_counts), 1)
        for ip, count in ip_counts.items():
            if count > avg_ip * 3:
                anomalies.append({
                    "type": "HIGH_FREQUENCY_SOURCE",
                    "detail": f"IP {ip} generated {count} incidents (avg={avg_ip:.1f})",
                    "severity": "HIGH",
                    "entity": ip
                })

        # Flag heavily targeted systems
        avg_sys = sum(system_counts.values()) / max(len(system_counts), 1)
        for sys, count in system_counts.items():
            if count > avg_sys * 3:
                anomalies.append({
                    "type": "TARGETED_SYSTEM",
                    "detail": f"System '{sys}' targeted {count} times (avg={avg_sys:.1f})",
                    "severity": "HIGH",
                    "entity": sys
                })

        # Flag burst hours
        avg_hour = sum(hourly_counts.values()) / max(len(hourly_counts), 1)
        for hour, count in hourly_counts.items():
            if count > avg_hour * 4:
                anomalies.append({
                    "type": "INCIDENT_BURST",
                    "detail": f"Hour {hour} saw {count} incidents (avg={avg_hour:.1f})",
                    "severity": "MEDIUM",
                    "entity": hour
                })

        return anomalies

    # ─── Risk Dashboard ─────────────────────────────────────────────────────────

    def generate_risk_dashboard(self) -> dict:
        """Generate a comprehensive risk dashboard for SOC teams."""
        summary = self.bc.get_chain_summary()
        validation = self.bc.validate_chain()
        anomalies = self.detect_anomalies()
        campaigns = self.correlate_attacks()

        all_incidents = self.bc.query_incidents()
        threat_scores = [self.ti.score_incident(inc) for inc in all_incidents]
        avg_threat = round(sum(threat_scores) / max(len(threat_scores), 1), 2)
        high_risk = [inc for inc in all_incidents
                     if self.ti.score_incident(inc) >= 25]

        return {
            "dashboard_generated_at": datetime.utcnow().isoformat() + "Z",
            "blockchain_integrity": "✅ INTACT" if validation["valid"] else "❌ TAMPERED",
            "chain_summary": summary,
            "threat_metrics": {
                "average_threat_score": avg_threat,
                "high_risk_incidents": len(high_risk),
                "active_campaigns_detected": len(campaigns),
                "anomalies_detected": len(anomalies)
            },
            "top_campaigns": campaigns[:5],
            "anomalies": anomalies,
            "high_risk_incident_ids": [inc["record_id"] for inc in high_risk[:10]]
        }
