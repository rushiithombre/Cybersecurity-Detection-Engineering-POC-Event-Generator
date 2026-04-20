<p align="center">
  <img src="https://img.shields.io/badge/version-3.0-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20FortiGate-informational?style=for-the-badge" />
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen?style=for-the-badge" />
</p>

<h1 align="center">🛡️ NEXUS SOC Toolkit</h1>
<p align="center"><b>Production-grade SOC attack simulation & security event trigger framework</b><br/>
Covers Windows Security · Linux auditd · FortiGate IPS · 260+ MITRE ATT&CK-mapped triggers</p>

---

> ⚠️ **LEGAL DISCLAIMER**
> This toolkit is designed **exclusively for authorized SOC lab testing, SIEM rule validation, and blue team training** in isolated, controlled environments. Never execute against systems you do not own or have explicit written permission to test. The authors accept no liability for misuse.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Repository Structure](#-repository-structure)
- [Scripts At a Glance](#-scripts-at-a-glance)
  - [NEXUS-SOC-EventTrigger.ps1](#1-nexus-soc-eventtriggerps1--windows)
  - [SOC-LinuxEventTrigger-v2.sh](#2-soc-linuxeventtrigger-v2sh--linux)
  - [fw-attack-trigger-v3.sh](#3-fw-attack-trigger-v3sh--fortigate--network)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [MITRE ATT&CK Coverage](#-mitre-attck-coverage)
- [Output & Reporting](#-output--reporting)
- [SIEM Integration](#-siem-integration)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 Overview

**NEXUS SOC Toolkit** is an open-source, production-grade security event simulation framework built for blue teams, SOC analysts, and detection engineers. It fires **real** attack-pattern events — not simulated log injections — across three key attack surfaces:

| Surface | Script | Events / Rules | MITRE Techniques |
|---|---|---|---|
| 🪟 Windows Security + Sysmon | `NEXUS-SOC-EventTrigger.ps1` | 130 Event IDs · 95 SIEM Rules | 40+ techniques |
| 🐧 Linux auditd + auth.log | `SOC-LinuxEventTrigger-v2.sh` | 62 SIEM Rules | 46 techniques |
| 🔥 FortiGate IPS + Network | `fw-attack-trigger-v3.sh` | 103 IPS Rules · 16 Categories | 50+ techniques |

**Why use this instead of commercial BAS tools?**

- ✅ **Free & open source** — no licensing fees, no agents to deploy
- ✅ **Real event generation** — actual Windows Event IDs, auditd syscalls, real network packets
- ✅ **SIEM-native** — built for QRadar, Splunk, LogRhythm — events land in your actual SIEM
- ✅ **Fully offline** — no CDN, no cloud dependency, runs air-gapped
- ✅ **Customizable** — add your own rules, categories, and MITRE mappings

---

## 📁 Repository Structure

```
nexus-soc-toolkit/
│
├── windows/
│   └── NEXUS-SOC-EventTrigger.ps1      # Windows Security event trigger
│
├── linux/
│   └── SOC-LinuxEventTrigger-v2.sh     # Linux auditd event trigger
│
├── network/
│   └── fw-attack-trigger-v3.sh         # FortiGate IPS / network attack trigger
│
├── docs/
│   ├── MITRE-COVERAGE.md               # Full MITRE ATT&CK technique matrix
│   ├── SIEM-INTEGRATION.md             # QRadar / Splunk / LogRhythm setup guides
│   └── LAB-SETUP.md                    # Recommended lab architecture
│
├── reports/                            # Auto-generated JSON/CSV/HTML reports (gitignored)
│
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── PULL_REQUEST_TEMPLATE.md
│
├── LICENSE
├── CONTRIBUTING.md
└── README.md
```

---

## 🧩 Scripts At a Glance

### 1. `NEXUS-SOC-EventTrigger.ps1` — Windows

> Production PowerShell framework that triggers real Windows Security and Sysmon events for SIEM rule validation.

**Key Stats:**
- 🪟 **130** Windows Security + Sysmon Event IDs
- 📋 **95** SIEM Correlation Rules
- 🗂️ **20** Attack Categories
- 🎯 **40+** MITRE ATT&CK Techniques
- 📊 Self-contained **NEXUS HTML Intelligence Dashboard** (no CDN required)

**Attack Categories:**

| # | Category | Key Event IDs | MITRE |
|---|---|---|---|
| 1 | Authentication | 4624, 4625, 4648, 4776 | T1078, T1110 |
| 2 | Disabled Account Login | 4625 (0xC000006E), 4768 | T1110 |
| 3 | Kerberos Attacks | 4649, 4672, 4673, 4768–4770 | T1558, T1003 |
| 4 | Account Lifecycle | 4720–4726, 4738, 4740 | T1136, T1531, T1098 |
| 5 | Group Management | 4727–4734 | T1069, T1098 |
| 6 | Active Directory Changes | 4662, 5136, 5137 (DCSync) | T1003.006 |
| 7 | Process Events | 4688, 4689, Sysmon 1/5/10 | T1059, T1055 |
| 8 | Lateral Movement | 4624 Type3, 5140, Sysmon 3 | T1021 |
| 9 | Object Access | 4656, 4660, 4663, 5145 | T1039 |
| 10 | Persistence | 4697, 4698, 4702, 7045 | T1543, T1053 |
| 11 | Policy Changes | 4719, 4739, 4946 | T1562 |
| 12 | Defense Evasion | 4719, 1102 (log clear) | T1562 |
| 13 | Ransomware | Sysmon 11/13/15, 4663 | T1486 |
| 14 | Malware Behavior | Sysmon 1/6/7/8/10, 4688 | T1059, T1055 |
| 15 | Discovery | Sysmon 1/22, 4688 | T1087, T1082 |
| 16 | Exfiltration | Sysmon 3/11/15, 5145 | T1048 |
| 17 | PowerShell Abuse | 4103, 4104, Sysmon 1 | T1059.001 |
| 18 | WMI Abuse | Sysmon 19/20/21, 4688 | T1047 |
| 19 | RDP Abuse | 4624 Type10, Sysmon 3 | T1021.001 |
| 20 | SIEM Rules Validator | 95 dedicated rule checks | All above |

**Requirements:**
- Windows Server 2016/2019/2022 or Windows 10/11
- PowerShell 5.1+, run as **Administrator**
- Optional: Sysmon (for full 95-rule coverage), Active Directory module

```powershell
# Run all categories
.\NEXUS-SOC-EventTrigger.ps1

# Run specific category
.\NEXUS-SOC-EventTrigger.ps1 -Category Authentication

# Dry run (zero changes)
.\NEXUS-SOC-EventTrigger.ps1 -DryRun

# High intensity + export report
.\NEXUS-SOC-EventTrigger.ps1 -Intensity High -ExportReport

# View last 2 hours of triggered events
.\NEXUS-SOC-EventTrigger.ps1 -ViewOnly -Hours 2
```

---

### 2. `SOC-LinuxEventTrigger-v2.sh` — Linux

> Production Bash framework that triggers real Linux security events via auditd syscalls, PAM, auth.log injection, and real process execution.

**Key Stats:**
- 🐧 **62** SIEM Correlation Rules (RULE-L01 to RULE-L62)
- 📋 **46** MITRE ATT&CK Techniques
- 🗂️ **13** Attack Categories + Full Kill Chain mode
- 📝 Log Sources: auditd, auth.log/secure, syslog, journald, cron, wtmp
- 🖥️ Interactive TUI category selector (arrow key navigation)

**Attack Categories:**

| # | Category | SIEM Rules | MITRE |
|---|---|---|---|
| 1 | Authentication | L01–L04 | T1110.001, T1078 |
| 2 | Account Management | L05–L08 | T1136, T1531, T1098 |
| 3 | Privilege Escalation | L09–L13 | T1548.001, T1548.002, T1548.003 |
| 4 | Execution / LOLBins | L14–L18 | T1059.004, T1055 |
| 5 | Persistence | L19–L24 | T1053, T1543, T1098.004 |
| 6 | Defense Evasion | L26–L31 | T1562.012, T1070.002, T1070.003, T1222 |
| 7 | Credential Access | L32–L36 | T1003.008, T1552.004, T1552 |
| 8 | Discovery | L37–L40 | T1046, T1082, T1087, T1552.005 |
| 9 | Lateral Movement | L41–L43 | T1021.004, T1071 |
| 10 | Exfiltration | L45–L49 | T1048, T1560, T1027 |
| 11 | Command & Control | L50–L52 | T1059.004, T1071.001, T1571 |
| 12 | Ransomware | L54–L58 | T1486, T1490 |
| 13 | Kernel / Rootkit | L59–L62 | T1547.006, T1562, T1055 |
| 🔗 | Kill Chain (All 5 Stages) | L01–L62 | Full ATT&CK chain |

**Requirements:**
- Linux: Kali, Ubuntu, RHEL/Rocky/CentOS
- Run as **root** (sudo)
- auditd running and active
- Optional: sshpass, nmap, nc, socat, strace

```bash
# Interactive category selector
sudo ./SOC-LinuxEventTrigger-v2.sh

# Run specific category
sudo ./SOC-LinuxEventTrigger-v2.sh --category Authentication

# Full kill chain simulation
sudo ./SOC-LinuxEventTrigger-v2.sh --category KillChain

# Dry run + export report
sudo ./SOC-LinuxEventTrigger-v2.sh --dry-run --report

# High intensity
sudo ./SOC-LinuxEventTrigger-v2.sh --intensity High --category Ransomware
```

---

### 3. `fw-attack-trigger-v3.sh` — FortiGate & Network

> Production Bash + Scapy framework that generates real offensive network traffic to validate FortiGate IPS signatures, firewall rules, and network SIEM detection.

**Key Stats:**
- 🔥 **103** FortiGate IPS / Network Attack Rules (FW-RULE-1 to FW-RULE-103)
- 🗂️ **16** Attack Categories
- 🎯 **50+** MITRE ATT&CK Techniques
- 🐍 Python/Scapy payloads for low-level packet crafting
- 📊 MITRE ATT&CK coverage matrix in terminal + CSV/JSON export

**Attack Categories:**

| # | Category | Rules | MITRE |
|---|---|---|---|
| 1 | Port Scanning | FW-001–007 | T1046 |
| 2 | SYN Flood | FW-008–013 | T1498 |
| 3 | UDP Flood | FW-014–018 | T1498.002 |
| 4 | ICMP Flood | FW-019–023 | T1499 |
| 5 | TCP Attacks | FW-024–031 | T1499.004 |
| 6 | Application Layer | FW-032–039 | T1190, T1059 |
| 7 | Evasion Techniques | FW-040–047 | T1036, T1027 |
| 8 | Reconnaissance | FW-048–055 | T1595, T1592 |
| 9 | Amplification Attacks | FW-056–063 | T1498.002 |
| 10 | Slow Attacks | FW-064–069 | T1499 |
| 11 | Lateral Movement | FW-070–077 | T1021 |
| 12 | Web Exploits | FW-078–085 | T1190, T1059 |
| 13 | C2 Simulation | FW-086–091 | T1071, T1573 |
| 14 | Credential Attacks | FW-092–097 | T1110 |
| 15 | FortiGate Specific | FW-098–101 | T1562 |
| 16 | Kill Chain | FW-102–103 | Full chain |

**Requirements:**
- Linux: Kali (recommended), Ubuntu
- Run as **root**
- hping3, nmap, python3 + scapy, masscan, curl, dig
- Target: isolated lab host (default 127.0.0.1)
- FortiGate in IPS monitoring path (optional — rules fire regardless)

```bash
# Run all attack categories
sudo ./fw-attack-trigger-v3.sh

# Run specific category
sudo ./fw-attack-trigger-v3.sh --category PortScan

# Dry run
sudo ./fw-attack-trigger-v3.sh --dry-run

# High intensity + export report
sudo ./fw-attack-trigger-v3.sh --intensity High --report

# Custom target IP
sudo ./fw-attack-trigger-v3.sh --target 192.168.1.100 --category SYNFlood
```

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                       NEXUS SOC TOOLKIT                            │
│                                                                    │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐  │
│  │  Windows     │   │  Linux       │   │  Network/FortiGate   │  │
│  │  EventTrig   │   │  EventTrig   │   │  Attack Trigger      │  │
│  │  (.ps1)      │   │  (.sh)       │   │  (.sh + scapy)       │  │
│  └──────┬───────┘   └──────┬───────┘   └──────────┬───────────┘  │
│         │                  │                       │              │
│         ▼                  ▼                       ▼              │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              Real Event Generation Layer                 │    │
│  │  Windows EIDs  │  auditd Syscalls  │  Network Packets    │    │
│  │  Sysmon Events │  auth.log / PAM   │  hping3/scapy/nmap  │    │
│  └──────────────────────────────────────────────────────────┘    │
│         │                  │                       │              │
│         ▼                  ▼                       ▼              │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │                 SIEM / Detection Layer                   │    │
│  │      IBM QRadar  │  Splunk  │  LogRhythm  │  Sentinel    │    │
│  └──────────────────────────────────────────────────────────┘    │
│         │                  │                       │              │
│         ▼                  ▼                       ▼              │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │                  Output & Reporting                      │    │
│  │  Terminal Log  │  JSON  │  CSV  │  NEXUS HTML Dashboard  │    │
│  └──────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────┘
```

### Event Flow

```
Script → Real OS/Network Action → Log Source → SIEM Correlation → Alert
   ↓
addresult() → JSON/CSV Report → NEXUS HTML Intelligence Dashboard
```

---

## ⚙️ Prerequisites

### All Scripts

| Requirement | Purpose |
|---|---|
| Isolated lab environment | **Mandatory** — never run in production |
| SIEM receiving logs | QRadar / Splunk / LogRhythm |
| Admin/root privileges | Required for all scripts |

### Windows (`NEXUS-SOC-EventTrigger.ps1`)

```powershell
# Check PowerShell version (5.1+ required)
$PSVersionTable.PSVersion

# Check Sysmon (recommended for full 95-rule coverage)
Get-Service -Name Sysmon* -ErrorAction SilentlyContinue

# Check Active Directory module
Get-Module -ListAvailable -Name ActiveDirectory
```

### Linux (`SOC-LinuxEventTrigger-v2.sh`)

```bash
# Check auditd
sudo systemctl status auditd

# Ubuntu/Debian
sudo apt-get install -y auditd sshpass nmap netcat-openbsd socat at zip dnsutils strace

# RHEL/Rocky/CentOS
sudo dnf install -y audit sshpass nmap ncat socat at zip bind-utils strace
```

### Network (`fw-attack-trigger-v3.sh`)

```bash
# Ubuntu/Kali
sudo apt-get install -y hping3 nmap python3-scapy masscan curl dnsutils

# Verify scapy
python3 -c "from scapy.all import *; print('Scapy OK')"
```

---

## 🚀 Quick Start

```bash
# 1. Clone
git clone https://github.com/yourusername/nexus-soc-toolkit.git
cd nexus-soc-toolkit

# 2. Linux — dry run first, then run
chmod +x linux/SOC-LinuxEventTrigger-v2.sh
sudo ./linux/SOC-LinuxEventTrigger-v2.sh --dry-run
sudo ./linux/SOC-LinuxEventTrigger-v2.sh --category Authentication

# 3. Network — dry run first, then run
chmod +x network/fw-attack-trigger-v3.sh
sudo ./network/fw-attack-trigger-v3.sh --dry-run
sudo ./network/fw-attack-trigger-v3.sh --category PortScan --target 127.0.0.1
```

```powershell
# Windows — open PowerShell as Administrator
cd windows
# Dry run first
.\NEXUS-SOC-EventTrigger.ps1 -DryRun

# Run Authentication
.\NEXUS-SOC-EventTrigger.ps1 -Category Authentication -Intensity Medium
```

---

## 📖 Usage

### Intensity Levels

| Level | Windows | Linux | Network |
|---|---|---|---|
| `Low` | BruteCount=3, StormCount=5 | Burst=3, Delay=0.5s | Low pps |
| `Medium` *(default)* | BruteCount=5, StormCount=8 | Burst=5, Delay=0.2s | Medium pps |
| `High` | BruteCount=10, StormCount=15 | Burst=10, Delay=0.1s | High pps |

### Report Output Formats

| Format | Content | Location |
|---|---|---|
| **Terminal** | Color-coded live output | stdout |
| **JSON** | Full results with timestamps | /tmp/socresults-XXXX.json (Linux) |
| **CSV** | Category, rule, status, method | /tmp/socresults-XXXX.csv (Linux) |
| **HTML** | NEXUS Intelligence Dashboard | Auto-opens in browser (Windows) |

### Terminal Color Codes

```
[TRIGGERED]   Green    — Event confirmed fired
[PARTIAL]     Yellow   — Fired but incomplete
[SKIPPED]     Gray     — Dependency missing
[ERROR]       Red      — Exception during execution
[DRY RUN]     Cyan     — Dry run print (zero changes)
!! SIEM !!    Red Bold — SIEM correlation rule fired
 KILL CHAIN   Magenta  — Kill chain stage marker
```

---

## 🎯 MITRE ATT&CK Coverage

### Combined Tactic Coverage (All 3 Scripts)

| Tactic | Techniques | Scripts |
|---|---|---|
| Initial Access | T1078, T1190, T1566 | PS, Linux, Network |
| Execution | T1059.001, T1059.004, T1047 | PS, Linux |
| Persistence | T1053, T1543, T1098.004 | PS, Linux |
| Privilege Escalation | T1548.001, T1548.002, T1548.003, T1134 | PS, Linux |
| Defense Evasion | T1027, T1036, T1070, T1562 | PS, Linux, Network |
| Credential Access | T1003, T1110, T1552, T1558 | PS, Linux, Network |
| Discovery | T1046, T1082, T1087, T1595 | PS, Linux, Network |
| Lateral Movement | T1021.001, T1021.004, T1550 | PS, Linux, Network |
| Collection | T1039, T1560 | PS, Linux |
| Command & Control | T1071, T1573, T1571 | PS, Linux, Network |
| Exfiltration | T1048, T1041 | Linux, Network |
| Impact | T1486, T1490, T1498, T1499 | Linux, Network |

> 📌 Full technique-to-rule mapping: [`docs/MITRE-COVERAGE.md`](docs/MITRE-COVERAGE.md)

---

## 🔗 SIEM Integration

### IBM QRadar

```
# AQL — Find triggered authentication events
SELECT * FROM events
WHERE LOGSOURCENAME(logsourceid) LIKE '%Windows%'
AND QIDNAME(qid) LIKE '%4625%'
START '2026-04-20 16:00:00' STOP '2026-04-20 17:00:00'
```

### Splunk

```spl
index=linux_syslog sourcetype=linux_secure
| search "Failed password"
| stats count by src_ip, user
| where count > 5
```

### Log Sources per Script

| Script | Log Sources | Collection Method |
|---|---|---|
| Windows PS | Security, System, Sysmon/Operational, PowerShell/Operational | WinRM / WEC / Syslog agent |
| Linux Bash | /var/log/auth.log, /var/log/audit/audit.log, syslog | rsyslog / Filebeat |
| Network FW | FortiGate IPS syslog, firewall policy logs | Syslog UDP/TCP 514 |

### JSON Report Schema

```json
{
  "timestamp": "2026-04-20T16:00:00Z",
  "category": "Authentication",
  "rule": "RULE-L01",
  "eventtype": "SSHBRUTEFORCE",
  "status": "triggered",
  "method": "logger+su+pam"
}
```

---

## 🗺️ Roadmap

### v3.0 — Current Release ✅

- [x] 95 Windows SIEM rules (NEXUS-SOC-EventTrigger.ps1)
- [x] 62 Linux SIEM rules (SOC-LinuxEventTrigger-v2.sh)
- [x] 103 FortiGate/Network IPS rules (fw-attack-trigger-v3.sh)
- [x] NEXUS HTML Intelligence Dashboard
- [x] JSON/CSV export reporting
- [x] MITRE ATT&CK mapping on all 260+ rules

### v4.0 — Planned 🔧

- [ ] **Detection Feedback Loop** — Auto-query QRadar/Splunk API, mark DETECTED/MISSED per rule
- [ ] **Scoring Engine** — Prevention %, Detection %, Mean Time to Detect (MTTD) per category
- [ ] **REST API Layer** — `POST /trigger/{platform}/{category}` via Flask/FastAPI
- [ ] **N8N Scheduler** — Daily automated runs + email/Slack report delivery
- [ ] **Container Escape Category** — cgroup, namespace, docker.sock (Linux)
- [ ] **Cloud Metadata Category** — AWS/Azure IMDS probe simulation
- [ ] **JSON Config-Driven Rules** — rules/*.json for no-code rule additions
- [ ] **Unified Dashboard** — Single HTML aggregating all 3 scripts

### v5.0 — Vision 🚀

- [ ] **AI Gap Analysis** — LLM-based detection gap recommendations
- [ ] **Threat Intel Feed** — Auto-update library from MITRE ATT&CK Navigator
- [ ] **Multi-Host Agent** — SSH-deployed agents for real lateral movement
- [ ] **NEXUS Web Platform** — Self-hosted full web UI (open source BAS)

---

## 🤝 Contributing

Contributions are welcome! Please read the guidelines before submitting.

### How to Contribute

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/add-container-escape`
3. **Follow** the code pattern for your script (see inline comments in each script)
4. **Test** with `--dry-run` before submitting
5. **Commit** with a descriptive message (see format below)
6. **Push** and open a **Pull Request**

### Commit Message Format

```
type(scope): short description

Types:  feat | fix | docs | refactor | test | chore
Scopes: windows | linux | network | docs | dashboard

Examples:
feat(linux): add RULE-L63 container escape via docker.sock
fix(windows): guard Add-Type with PSTypeName check for EID 4673
docs(mitre): add T1611 container escape to coverage matrix
```

### Code Style Rules

#### Bash (linux/ and network/)

```bash
# Mandatory block pattern:
info "Description of what fires..."
cmdrun <command> 2>/dev/null || true
trig "<auditd event or log entry that fired>"
siem "RULE-LXX" "Rule Name" "Description" "T-ID"
addresult "Category" "RULE-LXX" "EVENTTYPE" "triggered" "method"
```

- All test objects must use `soc` prefix (`$SOCUSER`, `$SOCDIR`, etc.)
- Objects must be cleaned in `cleanup()` EXIT trap
- New rules use next sequential `RULE-LXX` number
- MITRE IDs must be real and verified

#### PowerShell (windows/)

```powershell
# Mandatory block pattern:
T <EID> "Description"
if ($DryRun) { DRY }
else {
    try {
        # trigger command
        OK "EID fired + detail"
        Add-R <EID> "Category" "TRIGGERED" "Method" "T-ID"
    }
    catch {
        ERR $_.Exception.Message
        Add-R <EID> "Category" "ERROR" $_.Exception.Message "T-ID"
    }
}
P
```

- `Add-R` is **mandatory** in both `try` and `catch` paths
- `$adOK` must be checked before every AD cmdlet
- `Add-Type` must be guarded with PSTypeName existence check

### Bug Reports

Include in your issue:
- Script name and version
- OS and PowerShell/Bash version
- Command run (with `--dry-run` output if applicable)
- Expected vs actual behavior
- Full error output

### Feature Requests

Open an issue with `enhancement` label. Include:
- Attack technique or Event ID
- MITRE ATT&CK technique ID (verified)
- Which script(s) it applies to
- Expected log source for detection

---

## 📜 License

```
MIT License

Copyright (c) 2026 NEXUS SOC Toolkit Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## 👨‍💻 Author

Built by a SOC Analyst and Detection Engineer with 4+ years of hands-on experience across IBM QRadar, Splunk, LogRhythm, CrowdStrike, Palo Alto Cortex XDR, and FortiGate — for the blue team community.

---

<p align="center">
  Made with ❤️ for the Blue Team Community<br/>
  <b>Detect more. Miss less. Validate always.</b>
</p>
