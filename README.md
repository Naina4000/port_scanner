SOC Port Exposure Monitor

A SOC-focused multi-threaded port scanning and exposure analytics tool built in Python.
This project simulates how Security Operations Centers (SOC) identify, classify, prioritize, and monitor exposed services on network hosts.

Unlike a basic port scanner, this tool enriches open ports with risk intelligence, calculates an Attack Surface Index (ASI), performs trend tracking, and generates structured reports suitable for SOC workflows and SIEM integration

🚀 Key Features
🔎 Multi-Threaded Port Scanning

Concurrent TCP scanning using ThreadPoolExecutor

Configurable port range

Fast and efficient host analysis

🧠 Risk Intelligence Enrichment

External risk_database.json for intelligence mapping

Service classification (Low / Medium / High)

Severity scoring (numeric)

MITRE ATT&CK references

CVSS awareness

Recommended remediation guidance

📊 Exposure Analytics

Total Risk Score calculation

Overall Risk Level classification

Attack Surface Index (ASI) normalization (0–10 scale)

Risk distribution heatmap (percentage-based)

Top critical exposure ranking (prioritized list)

📈 Risk Trend Tracking

Compares current scan with previous scan

Detects Increased / Decreased / Stable risk

Logs trend events for monitoring

⚠ Alert Logic

Critical threshold detection

Structured logging for high-risk conditions

📂 Reporting & Integration

JSON structured report generation

SIEM-ready structured logging (scanner.log)

Continuous monitoring mode

SOC-Port-Exposure-Monitor/
│
├── file1.py # Main scanning and analytics engine
├── risk*database.json # Intelligence database
├── scanner.log # Structured log output
└── soc_monitor_report*\*.json # Generated reports

Design Principle

Intelligence Layer → risk_database.json

Processing & Analytics Layer → file1.py

This separation mimics real-world security tool architecture.

🛠 How It Works

Resolves target IP/domain.

Scans specified TCP port range using multi-threading.

Matches detected ports against risk database.

Calculates:

Risk Score

Overall Risk Level

Attack Surface Index

Risk Distribution

Ranks top critical exposures.

Tracks risk trend compared to previous scan.

Generates structured JSON report.

💻 Usage

Basic Scan
python file1.py -t 192.168.1.10

Custom Port Range
python file1.py -t 192.168.1.10 -sp 1 -ep 5000

Continuous Monitoring Mode
python file1.py -t 192.168.1.10 --monitor 60

This will rescan the host every 60 seconds.

📊 Sample Output
[OPEN] Port 445 | Risk: High | Severity: 10
[OPEN] Port 3389 | Risk: High | Severity: 9

Risk Distribution Heatmap:
High Risk: 66.67%
Medium Risk: 33.33%
Low Risk: 0%

Top Critical Exposures:

1. Port 445 | Severity: 10 | Risk: High | Service: SMB
2. Port 3389 | Severity: 9 | Risk: High | Service: RDP

SCAN SUMMARY
Total Open Ports: 3
Total Risk Score: 22
Overall Risk Level: High
Attack Surface Index: 7.33
Risk Trend: Increased

📄 Generated Report Structure

Example soc*monitor_report*<target>.json:

{
"target": "192.168.1.10",
"timestamp": "2026-02-26 22:15:00",
"summary": {
"total_open_ports": 3,
"total_risk_score": 22,
"overall_risk": "High",
"attack_surface_index": 7.33,
"alert_status": "NORMAL",
"risk_trend": "Increased",
"heatmap_distribution": {
"high_risk_percentage": 66.67,
"medium_risk_percentage": 33.33,
"low_risk_percentage": 0
}
},
"prioritized_exposures": [...],
"open_ports": [...]
}
