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
├── SPL-Queries/          ← All SPL detection queries
├── Investigation-Reports/ ← Markdown investigation reports
├── Incident-Reports/     ← Professional Word incident reports
├── Scenarios/            ← Advanced practice scenarios
├── Dashboards/           ← Splunk dashboard XML files
└── screenshots/          ← Evidence screenshots
```

---

## 🔍 Labs — 16 Attack Simulations

| # | Attack Simulated | Event ID | MITRE ATT&CK | Severity | Status |
|---|---|---|---|---|---|
| 1 | Brute Force Login | 4625 | T1110 | Medium | ✅ Completed |
| 2 | New User Account Created | 4720 | T1136 | High | ✅ Completed |
| 3 | Account Lockout | 4740 | T1110 | High | ✅ Completed |
| 4 | User Added to Admin Group | 4732 | T1098 | Critical | ✅ Completed |
| 5 | RDP & Interactive Login | 4624 | T1078 / T1021.001 | Medium-High | ✅ Completed |
| 6 | Suspicious PowerShell | 4104 | T1059.001 / T1027 | High-Critical | ✅ Completed |
| 7 | Process Creation | 4688 | T1059 / T1087 | High | ✅ Completed |
| 8 | Log Clearing | 1102 | T1070.001 | Critical | ✅ Completed |
| 9 | Firewall Disabled | 4104/4950 | T1562.004 | Critical | ✅ Completed |
| 10 | Scheduled Task Created | 4104/4698 | T1053.005 | High | ✅ Completed |
| 11 | Malicious Service Installed | 7045 | T1543.003 | Critical | ✅ Completed |
| 12 | Port Scan Detection | Firewall Log | T1046 | High | ✅ Completed |
| 13 | DNS Query Analysis | DNS Log | T1071.004 | High | ✅ Completed |
| 14 | SOC Security Dashboard | All Events | All | — | ✅ Completed |
| 15 | Splunk Alerts | All Events | All | — | ✅ Completed |
| 16 | Correlation Rules | All Events | Multiple | Critical | ✅ Completed |

---

## 🎯 Advanced Scenarios

| # | Scenario | MITRE ATT&CK | Severity | Status |
|---|---|---|---|---|
| 1 | Insider Threat Detection | T1136 / T1098 / T1070.001 | 🔴 Critical | ✅ Completed |
| 2 | Ransomware Simulation | T1486 / T1490 | 🔴 Critical | 🔜 Coming |
| 3 | Lateral Movement | T1021 / T1078 | 🔴 Critical | 🔜 Coming |
| 4 | Data Exfiltration | T1048 / T1071 | 🔴 Critical | 🔜 Coming |
| 5 | Phishing Attack | T1566 / T1059 | 🟠 High | 🔜 Coming |

---

## 🧪 Lab Highlights

### Lab 1 — Brute Force Detection
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, ComputerName
| where count >= 5
| sort -count
```
**Result:** 7 failed login attempts detected against account `hp`
📄 [Investigation Report](Investigation-Reports/brute_force_investigation.md)
![Raw Events](screenshots/01_raw_events.png)

---

### Lab 6 — Suspicious PowerShell + Threat Hunting
```spl
index=main EventCode=4104
| search Message="*Invoke*" OR Message="*WebClient*" OR Message="*ToBase64*"
| table _time, ComputerName, Message
| sort -_time
```
**Result:** Detected `Net.WebClient`, `Invoke-Expression`, `ToBase64String`
📄 [Investigation Report](Investigation-Reports/powershell_investigation_v2.md)

---

### Lab 16 — Correlation Rules
```spl
index=main sourcetype="WinEventLog:Security"
| eval event_type=case(EventCode="4625","Failed Login", EventCode="4624","Successful Login")
| stats count(eval(EventCode="4625")) as failed_count, count(eval(EventCode="4624")) as success_count by Account_Name, ComputerName
| where failed_count >= 3 AND success_count >= 1
| eval risk="HIGH — Possible Successful Brute Force!"
| table Account_Name, ComputerName, failed_count, success_count, risk
```
**Result:** Full attack chains detected including brute force success and evidence destruction

---

## 🎯 Scenario 01 — Insider Threat Detection

### Story
> A disgruntled employee creates a backdoor admin account before leaving, then clears logs to hide their tracks. SOC analyst must detect the full attack chain!

### Attack Chain Detected
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

### Result
**✅ TRUE POSITIVE — Complete Insider Threat Attack Chain Detected!**

📄 [Full Investigation Report](Investigation-Reports/insider_threat_IR-2026-002.md)
📄 [Scenario Details](Scenarios/Scenario_01_Insider_Threat/README.md)

![Insider Threat Detection](screenshots/insider_threat_detection.png)

---

## 📊 SOC Security Dashboard

Built a complete real-time SOC dashboard showing:

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

![SOC Dashboard](screenshots/32_soc_dashboard_panels.png)
![SOC Dashboard Charts](screenshots/33_soc_dashboard_charts.png)

---

## 🚨 Splunk Alerts

| Alert | Event ID | Severity | Status |
|---|---|---|---|
| Brute Force Detection | 4625 | 🟠 High | ✅ Enabled |
| Log Clearing — Critical | 1102 | 🔴 Critical | ✅ Enabled |
| New User Created | 4720 | 🟠 High | ✅ Enabled |
| Privilege Escalation | 4732 | 🔴 Critical | ✅ Enabled |
| Malicious Service Installed | 7045 | 🔴 Critical | ✅ Enabled |

![Alerts List](screenshots/36_splunk_alerts_list.png)
![Triggered Alerts](screenshots/37_splunk_triggered_alerts.png)

---

## 🎯 Skills Demonstrated

- Windows Security & System Event Log analysis
- PowerShell Script Block Log analysis
- Windows Firewall & DNS Log analysis
- Process Creation & Command Line logging
- Anti-forensics detection
- Defense evasion detection
- Persistence technique detection
- Privilege escalation detection
- Insider threat detection
- Malicious service detection
- Port scan & DNS C2 detection
- Advanced correlation rule development
- Multi-event attack chain detection
- SPL query writing and optimization
- Splunk Dashboard & Alert configuration
- MITRE ATT&CK framework mapping
- Professional incident documentation
- Threat hunting techniques

---

## 🏆 Certifications

| Certificate | Issuer | Date |
|---|---|---|
| SOC Level 1 Learning Path (65hrs) | TryHackMe | Apr 2026 |
| Cyber Job Simulation | Deloitte (Forage) | Apr 2026 |
| Cybersecurity Analyst Simulation | TATA (Forage) | Apr 2026 |
| Cyber Smart — Basic Cyber Security | Ministry of Home Affairs, India | May 2026 |

---

## 🚀 Coming Next

- [ ] Scenario 02 — Ransomware Simulation
- [ ] Scenario 03 — Lateral Movement Detection
- [ ] Scenario 04 — Data Exfiltration Detection
- [ ] Scenario 05 — Phishing Attack Detection
- [ ] BOTS (Boss of the SOC) Investigation

---

## 📬 Connect

**Jimil Joshi** — Aspiring SOC Analyst
🔗 [LinkedIn](https://www.linkedin.com/in/jimil-joshi-soc-analyst)
🔗 [GitHub](https://github.com/jimil-joshi-8115)
🔗 [TryHackMe](https://tryhackme.com)
