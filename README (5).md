# SOC-Lab-Splunk

A hands-on Security Operations Center (SOC) home lab built around Splunk Enterprise, focused on detection engineering, log analysis, and incident investigation. This repository documents 16 foundational detection labs and a 5-scenario simulated attack campaign mapped to the MITRE ATT&CK framework.

**Analyst:** Jimil Joshi
**Role:** SOC L1 Analyst (Fresher)
**Tools:** Splunk Enterprise (Search & Reporting), Windows Event Logs, PowerShell, CMD

---

## 📋 Table of Contents

- [Part 1: Foundational Detection Labs](#part-1-foundational-detection-labs)
- [Part 2: Simulated Attack Campaign (Scenarios)](#part-2-simulated-attack-campaign-scenarios)
- [Campaign Overview](#-campaign-overview)
- [Repository Structure](#-repository-structure)
- [Dashboards & Alerting](#-dashboards--alerting)
- [Certifications](#-certifications)
- [About](#-about)

---

## Part 1: Foundational Detection Labs

16 individual detection labs, each covering a specific Windows Security Event ID or attack technique. Each lab includes its own SPL query and investigation report.

| # | Lab | Event ID / Focus |
|---|---|---|
| 1 | Brute Force Detection | 4625 (Failed Logon) |
| 2 | New User Account Created | 4720 |
| 3 | Account Lockout | 4740 |
| 4 | Admin Group Membership Change | 4732 |
| 5 | RDP Login Detection | 4624 |
| 6 | Suspicious PowerShell Execution | 4104 |
| 7 | Process Creation Monitoring | 4688 |
| 8 | Log Clearing Detection | 1102 |
| 9 | Firewall Disabled Detection | — |
| 10 | Scheduled Task Creation | — |
| 11 | Malicious Service Installation | 7045 |
| 12 | Port Scan Detection | — |
| 13 | DNS Query Analysis | — |
| 14 | SOC Security Dashboard | — |
| 15 | Splunk Alerts (5 alerts configured) | Brute force alert triggered 6x |
| 16 | Correlation Rules (3 rules) | Multi-event correlation logic |

📁 All SPL queries: [`SPL-Queries/`](./SPL-Queries/)
📁 All investigation write-ups: [`Investigation-Reports/`](./Investigation-Reports/)
📁 Supporting screenshots: [`screenshots/`](./screenshots/)

---

## Part 2: Simulated Attack Campaign (Scenarios)

A 5-stage simulated attacker campaign, each scenario built as an independent investigation with its own README, SPL queries, investigation report, and formal incident report (Word document).

| # | Scenario | Incident ID | ATT&CK Stage | Status |
|---|---|---|---|---|
| 01 | [Insider Threat](./Scenarios/Scenario_01_Insider_Threat/) | IR-2026-002 | Initial Access (internal) | ✅ Complete |
| 02 | [Ransomware](./Scenarios/Scenario_02_Ransomware/) | IR-2026-003 | Impact | ✅ Complete |
| 03 | [Lateral Movement](./Scenarios/Scenario_03_Lateral_Movement/) | IR-2026-004 | Lateral Movement | ✅ Complete |
| 04 | [Data Exfiltration](./Scenarios/Scenario_04_Data_Exfiltration/) | IR-2026-005 | Exfiltration | ✅ Complete |
| 05 | [Phishing Attack Detection](./Scenarios/Scenario_05_Phishing_Attack/) | IR-2026-006 | Initial Access (external) | ✅ Complete |

### Scenario Summaries

**01 — Insider Threat (IR-2026-002):** Detected creation of a backdoor account followed by administrative privilege escalation and subsequent log clearing to cover tracks.

**02 — Ransomware (IR-2026-003):** Detected shadow copy deletion via `vssadmin`, a key ransomware pre-encryption technique. Includes a documented query-tuning lesson (false positives from `ren` substring matching legitimate Edge/WhatsApp processes) and a noted detection gap (shell builtins like `echo`/`ren` don't generate Event 4688 logs on their own).

**03 — Lateral Movement (IR-2026-004):** Detected admin share access (Network Logon Type 3) combined with WMI-based remote execution (`wmic /node:...`). Used Logon Type 2 vs. Type 3 behavioral baselining as supporting evidence.

**04 — Data Exfiltration (IR-2026-005):** Detected `Compress-Archive` staging followed by DNS tunneling (8 rapid `nslookup` queries with chunk-style subdomains to a simulated exfil domain). Identified that the DNS Client Operational log returned 0 events, requiring a pivot to Event 4688 process logs as an alternate evidence source.

**05 — Phishing Attack Detection (IR-2026-006):** Simulated a phishing-driven execution chain — malicious attachment trigger → LOLBin-based payload download via `certutil.exe` (`-urlcache -split -f`) → payload execution attempt. Identified certutil URL-cache abuse as the highest-confidence detection indicator, and documented a detection gap where the simulated dropped payload did not generate an independent execution event.

---

## 🗺️ Campaign Overview

The five scenarios form a single continuous simulated attack narrative, structured to mirror a realistic multi-stage intrusion:

```
Initial Access (External)     →  Scenario 05: Phishing Attack
        ↓
Initial Access (Internal)     →  Scenario 01: Insider Threat
        ↓
Lateral Movement              →  Scenario 03: Lateral Movement
        ↓
Data Exfiltration             →  Scenario 04: Data Exfiltration
        ↓
Impact                        →  Scenario 02: Ransomware
```

*Note: scenarios were built and numbered in development order (01–05); the campaign flow above represents the logical kill-chain sequence for narrative and portfolio purposes.*

**MITRE ATT&CK techniques covered across the campaign:**
T1566.001, T1204.002, T1105, T1078, T1098, T1070.001, T1490, T1021.002, T1047, T1560, T1071.004/T1048

---

## 📁 Repository Structure

```
SOC-Lab-Splunk/
├── README.md
├── SPL-Queries/                    # All SPL queries (16 labs + 5 scenarios)
├── Investigation-Reports/          # Markdown investigation write-ups (16 labs + 5 scenarios)
├── Incident-Reports/               # Formal Word doc incident reports (IR-2026-001 to IR-2026-006)
├── Scenarios/
│   ├── Scenario_01_Insider_Threat/
│   ├── Scenario_02_Ransomware/
│   ├── Scenario_03_Lateral_Movement/
│   ├── Scenario_04_Data_Exfiltration/
│   └── Scenario_05_Phishing_Attack/
├── Dashboards/
│   └── soc_security_dashboard.xml
└── screenshots/                    # 50+ supporting screenshots
```

---

## 📊 Dashboards & Alerting

- **SOC Security Dashboard** — centralized view of key security events (see [`Dashboards/soc_security_dashboard.xml`](./Dashboards/soc_security_dashboard.xml))
- **5 Splunk Alerts** configured, including a brute-force alert triggered 6 times during testing
- **3 Correlation Rules** combining multiple event types for higher-fidelity detection logic

---

## 🎓 Certifications

- TryHackMe SOC Level 1 (THM-7FX2PT6FWN, 65hrs 29min)
- Deloitte Cyber Job Simulation
- TATA Cybersecurity Analyst Job Simulation (IAM)
- Ministry of Home Affairs "Cyber Smart" Certification

---

## 👤 About

**Jimil Joshi**
SOC L1 Analyst (Fresher) | Gujarat University — CS/IT (2022–2026)
📍 Surat, Gujarat, India

🔗 [LinkedIn](https://linkedin.com/in/jimil-joshi-soc-analyst) · [GitHub](https://github.com/jimil-joshi-8115)

*This repository reflects hands-on, self-directed SOC lab work built independently using Splunk Enterprise on a personal home lab environment, with a focus on realistic detection engineering, transparent documentation of detection gaps/limitations, and MITRE ATT&CK-aligned investigation reporting.*
