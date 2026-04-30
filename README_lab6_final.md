# 🛡️ SOC Level 1 — Splunk Home Lab

> A hands-on SOC L1 home lab built to practice real-world threat detection, log analysis, and incident investigation using Splunk SIEM.

---

## 👨‍💻 About This Project

This repository documents my SOC Level 1 home lab where I simulate attacks on my own machine and use **Splunk** to detect, investigate, and report on them — just like a real SOC analyst would.

**Tools Used:**
- Splunk Enterprise (local)
- Windows Security Event Logs
- Windows PowerShell Operational Logs
- MITRE ATT&CK Framework

---

## 🔍 Investigations

| # | Attack Simulated | Event ID | MITRE ATT&CK | Severity | Status |
|---|---|---|---|---|---|
| 1 | Brute Force Login | 4625 | T1110 | Medium | ✅ Completed |
| 2 | New User Account Created | 4720 | T1136 | High | ✅ Completed |
| 3 | Account Lockout | 4740 | T1110 | High | ✅ Completed |
| 4 | User Added to Admin Group | 4732 | T1098 | Critical | ✅ Completed |
| 5 | RDP & Interactive Login | 4624 | T1078 / T1021.001 | Medium-High | ✅ Completed |
| 6 | Suspicious PowerShell | 4104 | T1059.001 / T1027 | High-Critical | ✅ Completed |

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

📄 [Full Investigation Report](Investigation-Reports/brute_force_investigation.md)

![Raw Events](screenshots/01_raw_events.png)
![Stats Table](screenshots/02_stats_table.png)

---

## 🧪 Lab 2 — New User Account Created (Persistence)

### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4720
| table _time, Account_Name, ComputerName, Security_ID
```
### Result
Splunk detected creation of backdoor account `hacker` by account `hp` on host `JIMIL-JOSHI`.

📄 [Full Investigation Report](Investigation-Reports/new_user_investigation.md)

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

📄 [Full Investigation Report](Investigation-Reports/account_lockout_investigation.md)

![Lockout Raw Event](screenshots/05_lockout_raw_event.png)
![Lockout Table](screenshots/06_lockout_table.png)

---

## 🧪 Lab 4 — User Added to Administrators Group (Privilege Escalation)

### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4732
| table _time, Account_Name, ComputerName, Security_ID, Member_Security_ID
```
### Result
Splunk detected **5 group membership change events** performed by account `hp` on host `JIMIL-JOSHI`.

📄 [Full Investigation Report](Investigation-Reports/admin_group_investigation.md)

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
Splunk detected **4 successful interactive logins** by account `hp` on host `JIMIL-JOSHI`.

📄 [Full Investigation Report](Investigation-Reports/rdp_login_investigation.md)

![RDP Raw Events](screenshots/09_rdp_raw_events.png)
![RDP Stats Table](screenshots/10_rdp_stats_table.png)

---

## 🧪 Lab 6 — Suspicious PowerShell Detection + Threat Hunting

### Part 1 — Basic Recon Detection

#### SPL Query
```spl
index=main EventCode=4104
| table _time, ComputerName, Message
| sort -_time
```

#### Commands Detected
- `net localgroup administrators` 🔴
- `Get-LocalUser` 🟡
- `whoami` 🟡
- `net user` 🟡
- `Get-Process` 🟡
- `ipconfig` 🟡

#### Result
Splunk detected **20 PowerShell events** including multiple recon commands on host `JIMIL-JOSHI`.

![PowerShell Raw Events](screenshots/11_powershell_raw_events.png)
![PowerShell Commands](screenshots/12_powershell_commands_detected.png)

---

### Part 2 — Advanced Threat Hunting

#### SPL Query
```spl
index=main EventCode=4104
| search Message="*Invoke*" OR Message="*WebClient*" OR Message="*ToBase64*" OR Message="*payload*" OR Message="*url*"
| table _time, ComputerName, Message
| sort -_time
```

#### High Risk Commands Detected
- `New-Object Net.WebClient` 🔴 Malware Download Technique
- `Invoke-Expression "whoami"` 🔴 Code Execution Technique
- `ToBase64String` 🔴 Obfuscation Technique
- `Write-Host "Connecting to $url"` 🟡 C2 Communication Pattern

#### Result
Splunk detected **5 high risk PowerShell events** — advanced attacker techniques confirmed!

📄 [Full Investigation Report](Investigation-Reports/powershell_investigation_v2.md)

![Threat Hunt Raw Events](screenshots/13_powershell_threat_hunt_raw.png)
![Threat Hunt Commands](screenshots/14_powershell_threat_hunt_commands.png)

---

## 🎯 Skills Demonstrated

- Windows Event Log analysis
- PowerShell Script Block Log analysis
- Splunk SPL query writing
- Threat detection and investigation
- Threat hunting for advanced attacker techniques
- MITRE ATT&CK framework mapping
- Incident documentation and reporting
- Persistence & privilege escalation detection
- PowerShell obfuscation detection

---

## 🚀 Coming Next

- [ ] Process Creation (Event ID 4688)
- [ ] Log Clearing (Event ID 1102)
- [ ] Windows Firewall Disabled (Event ID 4950)
- [ ] Scheduled Task Created (Event ID 4698)
- [ ] Service Installed (Event ID 7045)
- [ ] Port Scan Detection
- [ ] DNS Query Analysis
- [ ] Splunk Dashboard
- [ ] Splunk Alerts
- [ ] Correlation Rules

---

## 📬 Connect

**Jimil Joshi** — Aspiring SOC Analyst
🔗 [GitHub](https://github.com/jimil-joshi-8115)
