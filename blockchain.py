"""
Blockchain Core - Security Incident Logging System
Implements an immutable, tamper-evident blockchain for forensic evidence preservation.
"""

import hashlib
import json
import time
import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any


class MerkleTree:
    """Merkle Tree for efficient transaction verification."""

    def __init__(self, transactions: List[dict]):
        self.transactions = transactions
        self.root = self._build_tree([self._hash(tx) for tx in transactions])

    def _hash(self, data: Any) -> str:
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def _build_tree(self, leaves: List[str]) -> str:
        if not leaves:
            return self._hash("")
        if len(leaves) == 1:
            return leaves[0]
        if len(leaves) % 2 != 0:
            leaves.append(leaves[-1])
        pairs = [self._hash(leaves[i] + leaves[i + 1]) for i in range(0, len(leaves), 2)]
        return self._build_tree(pairs)


class IncidentRecord:
    """Represents a single security incident record stored in the blockchain."""

    SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    INCIDENT_TYPES = [
        "UNAUTHORIZED_ACCESS", "DATA_BREACH", "MALWARE_DETECTED",
        "DDoS_ATTACK", "PHISHING", "INSIDER_THREAT", "PRIVILEGE_ESCALATION",
        "NETWORK_INTRUSION", "RANSOMWARE", "ZERO_DAY_EXPLOIT", "OTHER"
    ]

    def __init__(self, incident_type: str, severity: str, source_ip: str,
                 target_system: str, description: str, evidence: Dict,
                 reporter_id: str, affected_assets: List[str] = None):
        self.record_id = str(uuid.uuid4())
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.incident_type = incident_type
        self.severity = severity
        self.source_ip = source_ip
        self.target_system = target_system
        self.description = description
        self.evidence = evidence  # dict: {type, content, hash}
        self.reporter_id = reporter_id
        self.affected_assets = affected_assets or []
        self.status = "OPEN"
        self.chain_of_custody = [
            {"action": "CREATED", "actor": reporter_id, "timestamp": self.timestamp}
        ]
        self.evidence_hash = self._compute_evidence_hash()

    def _compute_evidence_hash(self) -> str:
        evidence_str = json.dumps(self.evidence, sort_keys=True)
        return hashlib.sha256(evidence_str.encode()).hexdigest()

    def add_custody_event(self, action: str, actor: str):
        self.chain_of_custody.append({
            "action": action,
            "actor": actor,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })

    def to_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "incident_type": self.incident_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "target_system": self.target_system,
            "description": self.description,
            "evidence": self.evidence,
            "evidence_hash": self.evidence_hash,
            "reporter_id": self.reporter_id,
            "affected_assets": self.affected_assets,
            "status": self.status,
            "chain_of_custody": self.chain_of_custody
        }


class Block:
    """A block in the security incident blockchain."""

    def __init__(self, index: int, incidents: List[IncidentRecord],
                 previous_hash: str, miner_id: str = "SYSTEM"):
        self.index = index
        self.timestamp = time.time()
        self.incidents = incidents
        self.incident_dicts = [inc.to_dict() for inc in incidents]
        self.previous_hash = previous_hash
        self.miner_id = miner_id
        self.nonce = 0
        self.merkle_root = MerkleTree(self.incident_dicts).root
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        block_data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root,
            "previous_hash": self.previous_hash,
            "miner_id": self.miner_id,
            "nonce": self.nonce,
            "incident_count": len(self.incidents)
        }
        return hashlib.sha256(json.dumps(block_data, sort_keys=True).encode()).hexdigest()

    def mine_block(self, difficulty: int = 3):
        """Proof-of-Work mining with configurable difficulty."""
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.compute_hash()
        print(f"  [MINED] Block #{self.index} | Hash: {self.hash[:20]}... | Nonce: {self.nonce}")

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "timestamp": datetime.utcfromtimestamp(self.timestamp).isoformat() + "Z",
            "hash": self.hash,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "miner_id": self.miner_id,
            "nonce": self.nonce,
            "incident_count": len(self.incidents),
            "incidents": self.incident_dicts
        }


class SecurityBlockchain:
    """
    Immutable blockchain ledger for security incident logging and forensics.
    Supports mining, chain validation, incident querying, and forensic reporting.
    """

    def __init__(self, difficulty: int = 3, max_block_size: int = 10):
        self.difficulty = difficulty
        self.max_block_size = max_block_size
        self.chain: List[Block] = []
        self.pending_incidents: List[IncidentRecord] = []
        self.incident_index: Dict[str, dict] = {}  # record_id -> block info
        self._create_genesis_block()

    def _create_genesis_block(self):
        """Create the immutable genesis block."""
        genesis = Block(
            index=0,
            incidents=[],
            previous_hash="0" * 64,
            miner_id="GENESIS"
        )
        genesis.hash = hashlib.sha256(b"SECURITY_BLOCKCHAIN_GENESIS").hexdigest()
        self.chain.append(genesis)
        print(f"[GENESIS] Blockchain initialized | Hash: {genesis.hash[:20]}...")

    @property
    def latest_block(self) -> Block:
        return self.chain[-1]

    def log_incident(self, incident: IncidentRecord) -> str:
        """Add a new security incident to the pending pool."""
        self.pending_incidents.append(incident)
        print(f"  [LOGGED] Incident {incident.record_id[:8]}... | {incident.incident_type} | {incident.severity}")

        # Auto-mine if block is full or severity is CRITICAL
        if len(self.pending_incidents) >= self.max_block_size or incident.severity == "CRITICAL":
            return self.mine_pending_incidents()
        return incident.record_id

    def mine_pending_incidents(self, miner_id: str = "SYSTEM") -> str:
        """Mine all pending incidents into a new block."""
        if not self.pending_incidents:
            print("  [WARN] No pending incidents to mine.")
            return ""

        batch = self.pending_incidents[:self.max_block_size]
        self.pending_incidents = self.pending_incidents[self.max_block_size:]

        new_block = Block(
            index=len(self.chain),
            incidents=batch,
            previous_hash=self.latest_block.hash,
            miner_id=miner_id
        )
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

        # Index all incidents for fast lookup
        for inc in batch:
            self.incident_index[inc.record_id] = {
                "block_index": new_block.index,
                "block_hash": new_block.hash
            }

        return new_block.hash

    def validate_chain(self) -> Dict[str, Any]:
        """Validate the entire blockchain for tamper detection."""
        issues = []
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # Check hash linkage
            if current.previous_hash != previous.hash:
                issues.append(f"Block #{i}: broken hash link (previous_hash mismatch)")

            # Re-verify block hash
            expected_hash = current.compute_hash()
            if current.hash != expected_hash:
                issues.append(f"Block #{i}: hash tampered (stored={current.hash[:12]}... expected={expected_hash[:12]}...)")

            # Verify Merkle root
            expected_merkle = MerkleTree(current.incident_dicts).root
            if current.merkle_root != expected_merkle:
                issues.append(f"Block #{i}: Merkle root invalid (incidents may have been altered)")

        return {
            "valid": len(issues) == 0,
            "chain_length": len(self.chain),
            "total_incidents": sum(len(b.incidents) for b in self.chain),
            "issues": issues,
            "validated_at": datetime.utcnow().isoformat() + "Z"
        }

    def get_incident(self, record_id: str) -> Optional[dict]:
        """Retrieve a specific incident by ID with its block context."""
        if record_id not in self.incident_index:
            return None
        block_info = self.incident_index[record_id]
        block = self.chain[block_info["block_index"]]
        for inc in block.incident_dicts:
            if inc["record_id"] == record_id:
                return {
                    "incident": inc,
                    "block_index": block_info["block_index"],
                    "block_hash": block_info["block_hash"],
                    "immutable": True
                }
        return None

    def query_incidents(self, severity: str = None, incident_type: str = None,
                        source_ip: str = None, since: str = None) -> List[dict]:
        """Query incidents across the blockchain with filters."""
        results = []
        for block in self.chain[1:]:  # skip genesis
            for inc in block.incident_dicts:
                if severity and inc["severity"] != severity:
                    continue
                if incident_type and inc["incident_type"] != incident_type:
                    continue
                if source_ip and inc["source_ip"] != source_ip:
                    continue
                if since and inc["timestamp"] < since:
                    continue
                results.append({**inc, "block_index": block.index, "block_hash": block.hash})
        return results

    def get_chain_summary(self) -> dict:
        """Return a high-level summary of the blockchain state."""
        all_incidents = []
        for block in self.chain[1:]:
            all_incidents.extend(block.incident_dicts)

        severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        type_counts: Dict[str, int] = {}
        for inc in all_incidents:
            sev = inc.get("severity", "LOW")
            if sev in severity_counts:
                severity_counts[sev] += 1
            itype = inc.get("incident_type", "OTHER")
            type_counts[itype] = type_counts.get(itype, 0) + 1

        return {
            "total_blocks": len(self.chain),
            "total_incidents": len(all_incidents),
            "pending_incidents": len(self.pending_incidents),
            "severity_breakdown": severity_counts,
            "type_breakdown": type_counts,
            "genesis_hash": self.chain[0].hash,
            "latest_hash": self.latest_block.hash
        }

    def export_forensic_report(self, output_file: str = "forensic_report.json"):
        """Export a complete forensic report of the blockchain."""
        report = {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "system": "Blockchain Security Incident Logging System v1.0",
                "purpose": "Digital Forensics & Incident Response (DFIR)"
            },
            "chain_validation": self.validate_chain(),
            "chain_summary": self.get_chain_summary(),
            "blockchain": [block.to_dict() for block in self.chain]
        }
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  [EXPORT] Forensic report saved to '{output_file}'")
        return report
