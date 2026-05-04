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
| 8 | Log Clearing | 1102 | T1070.001 | Critical | ✅ Completed |
| 9 | Firewall Disabled | 4104/4950 | T1562.004 | Critical | ✅ Completed |
| 10 | Scheduled Task Created | 4104/4698 | T1053.005 | High | ✅ Completed |
| 11 | Malicious Service Installed | 7045 | T1543.003 | Critical | ✅ Completed |
| 12 | Port Scan Detection | Firewall Log | T1046 | High | ✅ Completed |

---

## 🧪 Lab 1 — Brute Force Detection

### What I Did
- Simulated multiple failed login attempts on Windows machine
- Used Splunk to search for Event ID 4625
- Wrote SPL query to detect and count failed logins per account

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

### What I Did
- Simulated attacker creating a backdoor local user account
- Used Splunk to detect Event ID 4720
- Identified who created the account, when and on which machine

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

### What I Did
- Enabled Windows account lockout policy (threshold = 3)
- Simulated brute force until account locked out
- Used Splunk to detect Event ID 4740
- Reset lockout policy back to 0 after lab

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

### What I Did
- Created a test user account
- Added test user to local Administrators group
- Used Splunk to detect Event ID 4732
- Removed test user and deleted after lab

### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4732
| table _time, Account_Name, ComputerName, Security_ID, Member_Security_ID
```

### Result
Splunk detected **5 group membership change events** by account `hp` on host `JIMIL-JOSHI`.

📄 [Full Investigation Report](Investigation-Reports/admin_group_investigation.md)

![Admin Group Raw Events](screenshots/07_admin_group_raw_events.png)
![Admin Group Security IDs](screenshots/08_admin_group_security_id.png)

---

## 🧪 Lab 5 — RDP & Interactive Login Detection

### What I Did
- Enabled Remote Desktop on Windows machine
- Simulated interactive login sessions
- Used Splunk to detect Event ID 4624 with Logon Type filtering
- Disabled RDP after lab

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

## 🧪 Lab 6 — Suspicious PowerShell + Threat Hunting

### Part 1 — Basic Recon Detection
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

## 🧪 Lab 7 — Process Creation Detection

### What I Did
- Enabled Process Creation and Command Line logging
- Simulated attacker recon commands via CMD
- Used Splunk to detect Event ID 4688
- Identified exact commands including `whoami` and `net localgroup administrators`

### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*cmd.exe*" OR New_Process_Name="*net.exe*" OR New_Process_Name="*whoami*"
| table _time, Account_Name, New_Process_Name, Process_Command_Line
| sort -_time
| head 10
```

### Result
Splunk detected **613 process creation events** with 4 high risk suspicious processes identified.

📄 [Full Investigation Report](Investigation-Reports/process_creation_investigation.md)

![Process Filtered](screenshots/15_process_creation_filtered.png)
![Process Stats](screenshots/16_process_creation_stats.png)
![Process CMD Line](screenshots/17_process_creation_cmdline.png)

---

## 🧪 Lab 8 — Log Clearing Detection

### What I Did
- Simulated attacker clearing Windows Security logs
- Used Splunk to detect Event ID 1102
- Demonstrated SIEM value — Splunk preserved all evidence!

### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=1102
| table _time, ComputerName, Account_Name, Message
| sort -_time
```

### Result
Splunk detected **2 log clearing events** — "The audit log was cleared" confirmed.

📄 [Full Investigation Report](Investigation-Reports/log_clearing_investigation.md)

![Log Clearing Raw Events](screenshots/18_log_clearing_raw_events.png)
![Log Clearing Table](screenshots/19_log_clearing_table.png)

---

## 🧪 Lab 9 — Windows Firewall Disabled

### What I Did
- Disabled Windows Firewall using PowerShell
- Used Splunk Event ID 4104 as alternative detection
- Detected exact firewall disable command
- Re-enabled firewall immediately after detection

### SPL Query
```spl
index=main EventCode=4104
| search Message="*NetFirewall*" OR Message="*Enabled False*" OR Message="*Enabled True*"
| table _time, ComputerName, Message
| sort -_time
| head 20
```

### Result
Splunk detected **74 firewall-related PowerShell events** including `Set-NetFirewallProfile -Enabled False`.

📄 [Full Investigation Report](Investigation-Reports/firewall_disabled_investigation.md)

![Firewall Commands](screenshots/20_firewall_commands_detected.png)
![Firewall Stats](screenshots/21_firewall_stats_table.png)

---

## 🧪 Lab 10 — Scheduled Task Created

### What I Did
- Created fake scheduled task named `WindowsUpdate`
- Task configured to run `cmd.exe /c whoami` on every logon as SYSTEM
- Used Splunk Event ID 4104 as alternative detection
- Deleted fake task after detection

### SPL Query
```spl
index=main EventCode=4104
| search Message="*schtasks*" OR Message="*ScheduledTask*" OR Message="*WindowsUpdate*"
| table _time, ComputerName, Message
| sort -_time
| head 20
```

### Result
Splunk detected **27 events** including suspicious task name `WindowsUpdate` on host `JIMIL-JOSHI`.

📄 [Full Investigation Report](Investigation-Reports/scheduled_task_investigation.md)

![Scheduled Task Detected](screenshots/22_scheduled_task_detected.png)
![Scheduled Task Stats](screenshots/23_scheduled_task_stats.png)

---

## 🧪 Lab 11 — Malicious Service Installed

### What I Did
- Created fake service named `FakeService`
- Service binary set to `cmd.exe /c whoami`
- Service configured as `auto start` with `LocalSystem` account
- Used Splunk to detect Event ID 7045
- Deleted fake service after detection

### SPL Query
```spl
index=main sourcetype="WinEventLog:System" EventCode=7045
| table _time, ComputerName, Message
| sort -_time
```

### What Splunk Found

| Field | Value |
|---|---|
| Service Name | FakeService |
| Service Binary | `cmd.exe /c whoami` 🔴 |
| Start Type | auto start 🔴 |
| Account | LocalSystem 🔴 |

📄 [Full Investigation Report](Investigation-Reports/service_installed_investigation.md)

![Service Raw Event](screenshots/24_service_installed_raw.png)
![Service Details](screenshots/25_service_installed_details.png)

---

## 🧪 Lab 12 — Port Scan Detection

### What I Did
- Enabled Windows Firewall logging
- Added firewall log to Splunk as monitored file
- Simulated port scan using PowerShell TcpClient connecting to ports 1-1024
- Used SPL regex to extract fields from raw firewall logs
- Identified open ports and scanning pattern

### SPL Query
```spl
index=main sourcetype="firewall_log"
| rex field=_raw "(?P<action>\w+)\s+(?P<protocol>\w+)\s+(?P<src_ip>[\d.]+)\s+(?P<dst_ip>[\d.]+)\s+(?P<src_port>\d+)\s+(?P<dst_port>\d+)"
| stats count by dst_port, action
| sort -count
| head 20
```

### Key Findings

| Port | Action | Count | Meaning |
|---|---|---|---|
| 8089 | ALLOW | 618 | 🔴 Open — Splunk Management |
| 1900 | DROP | 100 | ✅ Closed — Blocked |
| 5353 | ALLOW | 96 | 🔴 Open — DNS Service |
| 8000 | ALLOW | 32 | 🔴 Open — Splunk Web |

### Result
Splunk detected **1,527 firewall events** confirming port scan from `127.0.0.1` across 1024 ports.

📄 [Full Investigation Report](Investigation-Reports/port_scan_investigation.md)

![Port Scan Raw Events](screenshots/26_port_scan_raw_events.png)
![Port Scan IP Stats](screenshots/27_port_scan_ip_stats.png)
![Port Scan Ports](screenshots/28_port_scan_ports.png)

---

## 🎯 Skills Demonstrated

- Windows Security & System Event Log analysis
- PowerShell Script Block Log analysis
- Windows Firewall Log analysis
- Process Creation & Command Line logging
- Anti-forensics detection
- Defense evasion detection
- Persistence technique detection
- Privilege escalation detection
- Malicious service detection
- Scheduled task abuse detection
- Port scan detection
- SPL regex field extraction
- Layered detection strategy
- Living off the Land (LOL) attack detection
- MITRE ATT&CK framework mapping
- Incident documentation and reporting
- Threat hunting for advanced attacker techniques

---

## 🚀 Coming Next

- [ ] DNS Query Analysis
- [ ] Splunk Dashboard
- [ ] Splunk Alerts
- [ ] Correlation Rules

---

## 📬 Connect

**Jimil Joshi** — Aspiring SOC Analyst
🔗 [GitHub](https://github.com/jimil-joshi-8115)
