# 🔐 Blockchain-Based Secure Incident Logging & Digital Forensics System

## 📌 Overview

This project implements a **Blockchain-powered Security Incident Logging and Digital Forensics Framework** designed to ensure **tamper-proof, transparent, and immutable storage of security logs**.

Traditional logging systems are centralized and vulnerable to manipulation. This system leverages **blockchain technology** to preserve the integrity of digital evidence and improve the reliability of forensic investigations.

---

## 🚀 Features

* 🔗 **Immutable Blockchain Ledger**

  * Stores security incidents as blocks
  * Prevents tampering and unauthorized modification

* 🌳 **Merkle Tree Verification**

  * Efficient validation of incident data
  * Ensures data integrity within each block

* ⚒️ **Proof-of-Work Mining**

  * Secure block creation using configurable difficulty

* 🧾 **Incident Logging System**

  * Supports multiple incident types:

    * Unauthorized Access
    * Malware Detection
    * Data Breach
    * DDoS Attacks
    * Insider Threats

* 🔍 **Digital Forensics Engine**

  * Timeline reconstruction
  * Threat actor profiling
  * Attack correlation
  * Risk scoring

* 🧠 **Threat Intelligence Integration**

  * IP reputation analysis
  * Severity-based scoring
  * Known attack pattern detection

---

## 🏗️ Project Structure

```
📁 blockchain-forensics/
├── 📁 __pycache__/
│   ├── blockchain.cpython-311.pyc
│   └── forensics.cpython-311.pyc
│
├── 📁 .vscode/
│   └── settings.json
│
├── 📄 blockchain.py        # Core blockchain implementation
├── 📄 demo.py              # Simulation of cyber attack scenarios
├── 📄 forensics.py         # Forensics engine & threat analysis
├── 📄 forensic_report.json # Generated forensic analysis report
└── 📄 README.md            # Project documentation
```

---

## ⚙️ How It Works

1. **Incident Generation**

   * Security events are captured as `IncidentRecord` objects

2. **Logging**

   * Incidents are added to a pending pool

3. **Block Creation**

   * Incidents are grouped into blocks
   * Merkle root is generated

4. **Mining**

   * Proof-of-Work algorithm secures the block

5. **Blockchain Storage**

   * Blocks are linked using hashes
   * Ensures immutability

6. **Forensic Analysis**

   * Investigators analyze stored logs
   * Generate timelines and threat insights

---

## 🧪 Demo Simulation

The `demo.py` script simulates a **multi-stage cyber attack scenario**, including:

* Network intrusion
* Brute force attack
* Malware (Ransomware)
* Data exfiltration
* Privilege escalation
* Insider threats
* DDoS attacks
* Zero-day exploits

Run the demo:

```bash
python demo.py
```

---

## 🛠️ Installation

1. Clone the repository:

```bash
git clone https://github.com/your-username/blockchain-forensics.git
cd blockchain-forensics
```

2. Run the project:

```bash
python demo.py
```

---

## 📊 Key Components

### 🔹 Blockchain Core

* Block structure with hash linking
* Merkle Tree for integrity
* Mining mechanism

### 🔹 Incident Record

* Unique ID
* Timestamp
* Evidence hash
* Chain of custody tracking

### 🔹 Forensics Engine

* Timeline reconstruction
* Threat scoring
* Attack correlation

---

## 🔐 Security Benefits

* ✅ Tamper-proof logs
* ✅ Transparent evidence tracking
* ✅ Strong chain of custody
* ✅ Improved forensic reliability

---

## 📚 Use Cases

* Cybersecurity monitoring systems
* Digital forensic investigations
* Cloud security logging
* IoT device logging
* Enterprise threat analysis

---

## 📖 Research Background

This project is based on the concept of:

**"Blockchain-Enabled Secure Incident Logging and Digital Forensics Framework"** 

It addresses the limitations of centralized logging systems by introducing decentralized, secure log storage.


---

## 📌 Future Enhancements

* Integration with real SIEM tools
* Web-based dashboard
* Smart contract automation
* Distributed blockchain network
* AI-based anomaly detection

---

