# 🛡️ SOC Level 1 — Splunk Home Lab

> A hands-on SOC L1 home lab built to practice real-world threat detection, log analysis, and incident investigation using Splunk SIEM.

---

## 👨‍💻 About This Project

This repository documents my SOC Level 1 home lab where I simulate attacks on my own machine and use **Splunk** to detect, investigate, and report on them — just like a real SOC analyst would.

**Tools Used:**
- Splunk Enterprise (local)
- Windows Security Event Logs
- MITRE ATT&CK Framework

---

## 🔍 Investigations

| # | Attack Simulated | Event ID | MITRE ATT&CK | Severity | Status |
|---|---|---|---|---|---|
| 1 | Brute Force Login | 4625 | T1110 | Medium | ✅ Completed |
| 2 | New User Account Created | 4720 | T1136 | High | ✅ Completed |
| 3 | Account Lockout | 4740 | T1110 | High | ✅ Completed |
| 4 | User Added to Admin Group | 4732 | T1098 | Critical | ✅ Completed |

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

### Screenshots
![Raw Events](screenshots/01_raw_events.png)
![Stats Table](screenshots/02_stats_table.png)

---

## 🧪 Lab 2 — New User Account Created (Persistence)

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

### Screenshots
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
Splunk detected account lockout of `hp` on host `JIMIL-JOSHI` at 08:58:06 on 29/04/2026.

📄 [Full Investigation Report](Investigation-Reports/account_lockout_investigation.md)

### Screenshots
![Lockout Raw Event](screenshots/05_lockout_raw_event.png)
![Lockout Table](screenshots/06_lockout_table.png)

---

## 🧪 Lab 4 — User Added to Administrators Group (Privilege Escalation)

### What I Did
- Created a test user account
- Added test user to local Administrators group
- Used Splunk to detect Event ID 4732
- Identified who performed the action and full Security ID details
- Removed test user from Administrators group and deleted after lab

### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4732
| table _time, Account_Name, ComputerName, Security_ID, Member_Security_ID
```

### Result
Splunk detected **5 group membership change events** performed by account `hp` on host `JIMIL-JOSHI` — confirming privilege escalation simulation.

📄 [Full Investigation Report](Investigation-Reports/admin_group_investigation.md)

### Screenshots
![Admin Group Raw Events](screenshots/07_admin_group_raw_events.png)
![Admin Group Security IDs](screenshots/08_admin_group_security_id.png)

---

## 🎯 Skills Demonstrated

- Windows Event Log analysis
- Splunk SPL query writing
- Threat detection and investigation
- MITRE ATT&CK framework mapping
- Incident documentation and reporting
- Persistence technique detection
- Privilege escalation detection
- Account lockout investigation

---

## 🚀 Coming Next

- [ ] RDP Login Detection (Event ID 4624)
- [ ] Suspicious PowerShell (Event ID 4104)
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
