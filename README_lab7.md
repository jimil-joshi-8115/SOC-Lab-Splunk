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
| 7 | Process Creation | 4688 | T1059 / T1087 | High | ✅ Completed |

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

## 🧪 Lab 2 — New User Account Created
### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4720
| table _time, Account_Name, ComputerName, Security_ID
```
### Result
Splunk detected creation of backdoor account `hacker` by `hp` on `JIMIL-JOSHI`.
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

## 🧪 Lab 4 — User Added to Administrators Group
### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4732
| table _time, Account_Name, ComputerName, Security_ID, Member_Security_ID
```
### Result
Splunk detected **5 group membership changes** by `hp` on `JIMIL-JOSHI`.
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
Splunk detected **4 successful interactive logins** by `hp` on `JIMIL-JOSHI`.
📄 [Full Investigation Report](Investigation-Reports/rdp_login_investigation.md)
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
Splunk detected **20 PowerShell recon events** including `whoami`, `net user`, `Get-LocalUser`.

### Part 2 — Advanced Threat Hunting
```spl
index=main EventCode=4104
| search Message="*Invoke*" OR Message="*WebClient*" OR Message="*ToBase64*" OR Message="*payload*"
| table _time, ComputerName, Message
| sort -_time
```
Splunk detected **5 high risk events** — `Net.WebClient`, `Invoke-Expression`, `ToBase64String`.

📄 [Full Investigation Report](Investigation-Reports/powershell_investigation_v2.md)
![PowerShell Raw Events](screenshots/11_powershell_raw_events.png)
![PowerShell Commands](screenshots/12_powershell_commands_detected.png)
![Threat Hunt Raw](screenshots/13_powershell_threat_hunt_raw.png)
![Threat Hunt Commands](screenshots/14_powershell_threat_hunt_commands.png)

---

## 🧪 Lab 7 — Process Creation Detection (Living off the Land)

### What I Did
- Enabled Process Creation logging and Command Line logging via auditpol
- Simulated attacker recon commands via CMD
- Used Splunk to detect Event ID 4688
- Identified exact commands run including `whoami` and `net localgroup administrators`
- Detected Living off the Land (LOL) attack technique

### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*cmd.exe*" OR New_Process_Name="*net.exe*" OR New_Process_Name="*whoami*"
| table _time, Account_Name, New_Process_Name, Process_Command_Line
| sort -_time
| head 10
```

### Suspicious Processes Detected
- `whoami.exe` — `whoami` 🔴
- `net.exe` — `net localgroup administrators` 🔴
- `cmd.exe` — `cmd.exe /c "ver"` 🟡

### Result
Splunk detected **613 process creation events** with **4 high risk suspicious processes** identified on host `JIMIL-JOSHI`.

📄 [Full Investigation Report](Investigation-Reports/process_creation_investigation.md)

![Process Filtered](screenshots/15_process_creation_filtered.png)
![Process Stats](screenshots/16_process_creation_stats.png)
![Process CMD Line](screenshots/17_process_creation_cmdline.png)

---

## 🎯 Skills Demonstrated

- Windows Event Log analysis
- PowerShell Script Block Log analysis
- Process Creation & Command Line logging
- Splunk SPL query writing
- Threat detection and investigation
- Threat hunting for advanced attacker techniques
- Living off the Land (LOL) attack detection
- MITRE ATT&CK framework mapping
- Incident documentation and reporting

---

## 🚀 Coming Next

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
