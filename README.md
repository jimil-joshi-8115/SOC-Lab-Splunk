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
│   └── brute_force_detection.spl
│
├── Investigation-Reports/
│   └── brute_force_investigation.md
│
└── screenshots/
    ├── 01_raw_events.png
    └── 02_stats_table.png
```

---

## 🔍 Investigations

| # | Attack Simulated | Event ID | MITRE ATT&CK | Status |
|---|---|---|---|---|
| 1 | Brute Force Login | 4625 | T1110 | ✅ Completed |

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

## 📸 Screenshots

### Raw Events in Splunk
![Raw Events](screenshots/01_raw_events.png)

### Stats Table — Failed Logins by Account
![Stats Table](screenshots/02_stats_table.png)

---

## 🎯 Skills Demonstrated

- Windows Event Log analysis
- Splunk SPL query writing
- Threat detection and investigation
- MITRE ATT&CK framework mapping
- Incident documentation and reporting

---

## 🚀 Coming Next

- [ ] Suspicious PowerShell detection (Event ID 4104)
- [ ] New user account created (Event ID 4720)
- [ ] Port scan detection
- [ ] Splunk dashboard creation

---

## 📬 Connect

**Jimil Joshi** — Aspiring SOC Analyst
