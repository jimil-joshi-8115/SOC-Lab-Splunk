# 🔍 Investigation Report — Brute Force Login Attempt

## Overview

| Field | Details |
|---|---|
| **Date** | 27 April 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Event ID** | 4625 — Failed Login |
| **MITRE ATT&CK** | T1110 — Brute Force |
| **Severity** | Medium |
| **Status** | Investigated — Simulated Attack (Lab) |

---

## 1. Alert Description

Splunk detected multiple failed login attempts (Event ID 4625) on host `JIMIL-JOSHI` within a 60 minute window. A total of **7 failed login events** were recorded against account `hp`.

---

## 2. Detection Query Used

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, ComputerName
| sort -count
```

---

## 3. Findings

| Account_Name | ComputerName | Failed Attempts |
|---|---|---|
| hp | JIMIL-JOSHI | 7 |
| JIMIL-JOSHI$ | JIMIL-JOSHI | 7 |

- Account `hp` had **7 consecutive failed logins** — consistent with a brute force pattern
- Account `JIMIL-JOSHI$` is a machine account — normal system behavior, not suspicious
- All events originated from the same host `JIMIL-JOSHI`

---

## 4. Timeline of Events

| Time | Event |
|---|---|
| 16:14:44 | First failed login attempt detected |
| 16:26:58 | Last failed login attempt recorded |
| ~60 mins | Total window of failed attempts |

---

## 5. Analysis

Event ID 4625 is generated every time a Windows account fails to authenticate. A pattern of **5 or more failures** in a short window is a strong indicator of:

- Manual brute force attempt
- Credential stuffing
- Automated login attack tool

In this case, the activity was a **simulated brute force** performed in a controlled lab environment to test detection capability.

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force | T1110 |
| Credential Access | Password Guessing | T1110.001 |

---

## 7. Conclusion

The Splunk detection rule successfully identified the brute force simulation. The SPL query detected failed logins and grouped them by account and host, allowing an analyst to quickly identify the targeted account and machine.

**Verdict: True Positive — Brute Force Simulation Detected ✅**

---

## 8. Recommendations

- Set Splunk alert to trigger when `count >= 5` failed logins within 10 minutes
- Enable account lockout policy on Windows (lock after 5 failed attempts)
- Monitor for Event ID 4624 (successful login) immediately after multiple 4625s — may indicate successful brute force

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/01_raw_events.png` | 7 raw failed login events in Splunk |
| `screenshots/02_stats_table.png` | Stats table showing account and count |
