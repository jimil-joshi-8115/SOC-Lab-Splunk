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

## 📁 Repository Structure

```
SOC-Lab-Splunk/
│
├── README.md
│
├── SPL-Queries/
│   ├── brute_force_detection.spl
│   └── new_user_detection.spl
│
├── Investigation-Reports/
│   ├── brute_force_investigation.md
│   └── new_user_investigation.md
│
└── screenshots/
    ├── 01_raw_events.png
    ├── 02_stats_table.png
    ├── 03_new_user_raw_event.png
    └── 04_new_user_table.png
```

---

## 🔍 Investigations

| # | Attack Simulated | Event ID | MITRE ATT&CK | Status |
|---|---|---|---|---|
| 1 | Brute Force Login | 4625 | T1110 | ✅ Completed |
| 2 | New User Account Created | 4720 | T1136 | ✅ Completed |

---

## 🧪 Lab 1 — Brute Force Detection

### What I Did
- Simulated multiple failed login attempts on Windows machine
- Used Splunk to search for Event ID 4625
- Wrote SPL query to detect and count failed logins per account
- Documented full investigation report

### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, ComputerName
| where count >= 5
| sort -count
```

### Result
Splunk successfully detected **7 failed login attempts** against account `hp` on host `JIMIL-JOSHI` within a 60 minute window.

📄 [Full Investigation Report](Investigation-Reports/brute_force_investigation.md)

---

## 📸 Lab 1 Screenshots

### Raw Events in Splunk
![Raw Events](screenshots/01_raw_events.png)

### Stats Table — Failed Logins by Account
![Stats Table](screenshots/02_stats_table.png)

---

## 🧪 Lab 2 — New User Account Created (Persistence)

### What I Did
- Simulated attacker creating a backdoor local user account
- Used Splunk to detect Event ID 4720
- Identified who created the account, when and on which machine
- Documented full investigation report

### SPL Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4720
| table _time, Account_Name, ComputerName, Security_ID
```

### Result
Splunk successfully detected creation of backdoor account `hacker` by account `hp` on host `JIMIL-JOSHI` at 17:26:51 on 28/04/2026.

📄 [Full Investigation Report](Investigation-Reports/new_user_investigation.md)

---

## 📸 Lab 2 Screenshots

### Raw Event — New User Created
![New User Raw Event](screenshots/03_new_user_raw_event.png)

### Table View — Account Details
![New User Table](screenshots/04_new_user_table.png)

---

## 🎯 Skills Demonstrated

- Windows Event Log analysis
- Splunk SPL query writing
- Threat detection and investigation
- MITRE ATT&CK framework mapping
- Incident documentation and reporting
- Persistence technique detection

---

## 🚀 Coming Next

- [ ] Suspicious PowerShell detection (Event ID 4104)
- [ ] Port scan detection
- [ ] Splunk dashboard creation

---

## 📬 Connect

**Jimil Joshi** — Aspiring SOC Analyst  
🔗 [GitHub](https://github.com/jimil-joshi-8115)
