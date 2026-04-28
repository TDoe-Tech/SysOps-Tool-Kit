# SysOps Toolkit

A unified IT operations dashboard demonstrating my skills across CompTIA **A+**, **Network+**, and **Security+** certifications.

> I built a unified IT operations dashboard to demonstrate my skills across CompTIA A+, Network+, and Security+ domains, combining system troubleshooting, networking concepts, and security fundamentals into a single project.

\---

## Certification Coverage

|Module|Cert|Topics Demonstrated|
|-|-|-|
|`hardware/`|CompTIA A+|Hardware diagnostics, disk health (S.M.A.R.T.), CPU/RAM/temp monitoring, troubleshooting methodology|
|`network/`|CompTIA Network+|Host discovery, subnetting/CIDR, MAC OUI lookup, TCP/IP layers, topology mapping|
|`security/`|CompTIA Security+|Log parsing, threat detection, MITRE ATT\&CK mapping, brute-force/privesc detection, incident response|

\---

## Features

### A+ Module - Hardware Diagnostics

* Real-time CPU usage, temperature, and core count
* RAM usage with available/total breakdown
* Disk health via S.M.A.R.T. status and usage percentage
* Pass/Fail diagnostic report exportable as HTML

### Net+ Module - Network Analysis

* Local network host discovery using Nmap
* MAC address OUI vendor lookup
* Subnet calculator (CIDR → host range, broadcast, usable IPs)
* Topology visualization saved as PNG

### Sec+ Module - Threat Intelligence

* Windows Event Log ingestion and normalization
* Rule-based detection: brute force, privilege escalation, account lockout
* Each alert mapped to a MITRE ATT\&CK technique ID
* Dashboard view with severity ratings

\---

## Tech Stack

* **Python 3.10+**
* **Flask** — web dashboard
* **psutil** — hardware metrics
* **python-nmap** — network scanning
* **networkx + matplotlib** — topology graphs
* **Jinja2** — HTML report templates

\---

## Setup

```bash
# Clone the repo
git clone https://github.com/TDoe-Tech/SysOps-Tool-Kit.git
cd SysOps-Tool-Kit

# Install dependencies
pip install -r requirements.txt

# Run the dashboard
python app.py
```

Then open `http://localhost:5000` in your browser.

> \*\*Note:\*\* Network scanning requires Nmap installed on your system.
> - Linux/macOS: `sudo apt install nmap` or `brew install nmap`
> - Windows: Download from https://nmap.org/download.html

\---

## Running Individual Modules (CLI)

```bash
# A+ — Hardware report
python hardware/diagnostics.py

# Net+ — Scan local network
python network/scanner.py --subnet 192.168.1.0/24

# Net+ — Subnet calculator
python network/subnet\_calc.py --cidr 192.168.1.0/24

# Sec+ — Analyze sample logs
python security/ingest.py --log sample\_logs/windows\_events.json
```

\---

## Project Structure

```
sysops-toolkit/
├── app.py                    # Flask app — main dashboard
├── requirements.txt
├── README.md
│
├── hardware/
│   ├── diagnostics.py        # CPU, RAM, disk, temp collector
│   └── report.py             # HTML report generator
│
├── network/
│   ├── scanner.py            # Nmap host discovery
│   ├── subnet\_calc.py        # CIDR subnet calculator
│   └── topology.py           # Network graph visualizer
│
├── security/
│   ├── ingest.py             # Log parser + normalizer
│   ├── detections.py         # Rule-based alert engine
│   └── mitre.py              # MITRE ATT\&CK technique mapper
│
├── sample\_logs/
│   └── windows\_events.json   # Sanitized sample log data
│
└── templates/
    ├── base.html
    ├── index.html
    ├── hardware.html
    ├── network.html
    └── security.html
```

\---

## Screenshots

<img width="1389" height="862" alt="image" src="https://github.com/user-attachments/assets/66765999-6b19-4e3a-a0dd-e00e5180061b" />

<img width="1389" height="728" alt="image" src="https://github.com/user-attachments/assets/c666a1ea-2fc8-4c71-83d1-4e4568f767d9" />

<img width="1390" height="859" alt="image" src="https://github.com/user-attachments/assets/7d01e292-8844-40ad-a5c0-10cc209a686a" />

<img width="1378" height="859" alt="image" src="https://github.com/user-attachments/assets/25cf3a48-3f18-4bb7-a087-d95a0b2b5cd6" />

\---

## License

MIT — free to use, fork, and build on.

