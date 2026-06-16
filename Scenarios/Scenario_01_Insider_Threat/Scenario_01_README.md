# 🎯 Scenario 01 — Insider Threat Detection

## Scenario Overview

| Field | Details |
|---|---|
| **Scenario Name** | Insider Threat |
| **Difficulty** | Medium |
| **Date** | 15 June 2026 |
| **Analyst** | Jimil Joshi |
| **Tools Used** | Splunk Enterprise, Windows Event Logs |
| **MITRE ATT&CK** | T1136, T1098, T1070.001 |
| **Severity** | 🔴 Critical |

---

## Scenario Story

> A disgruntled employee is about to leave the company. Before leaving, they create a backdoor admin account to maintain access after their departure, then clear the security logs to hide their tracks. Your job as SOC L1 analyst is to detect this activity using Splunk!

---

## Attack Chain Simulated

```
Step 1 → Create backdoor user account (insider)
Step 2 → Add account to Administrators group
Step 3 → Clear Security Event Logs
```

---

## Commands Used to Simulate

```cmd
REM Step 1 - Create backdoor user
net user insider Password123! /add

REM Step 2 - Escalate to admin
net localgroup Administrators insider /add

REM Step 3 - Clear logs (cover tracks)
wevtutil cl Security
```

---

## Detection Query

```spl
index=main sourcetype="WinEventLog:Security"
(EventCode=4720 OR EventCode=4732 OR EventCode=4625 OR EventCode=1102)
| eval Attack=case(
    EventCode="4720","1-New User Created",
    EventCode="4732","2-Added to Admins",
    EventCode="4625","3-Failed Logins",
    EventCode="1102","4-Log Clearing")
| stats count by Attack, Account_Name, ComputerName
| sort Attack
```

---

## Results

| Attack Stage | Account | Computer | Count |
|---|---|---|---|
| 1-New User Created | insider | JIMIL-JOSHI | 1 🔴 |
| 2-Added to Admins | hp | JIMIL-JOSHI | 2 🔴 |
| 4-Log Clearing | hp | JIMIL-JOSHI | 1 🔴 |

---

## Verdict

**✅ TRUE POSITIVE — Insider Threat Confirmed**

---

## Files in This Scenario

| File | Description |
|---|---|
| `README.md` | This file — scenario overview |
| `screenshots/insider_threat_detection.png` | Splunk detection screenshot |

---

## Related Files

| File | Location |
|---|---|
| SPL Query | `SPL-Queries/insider_threat_detection.spl` |
| Investigation Report | `Investigation-Reports/insider_threat_IR-2026-002.md` |
| Incident Report | `Incident-Reports/IR-2026-002_Insider_Threat.docx` |

---

## 📄 Full Investigation Report

📄 [IR-2026-002 — Insider Threat Investigation](../../Investigation-Reports/insider_threat_IR-2026-002.md)

---

## Screenshot

![Insider Threat Detection](screenshots/insider_threat_detection.png)
