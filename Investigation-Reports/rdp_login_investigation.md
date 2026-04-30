# 🔍 Investigation Report — RDP & Interactive Login Detection

## Overview

| Field | Details |
|---|---|
| **Date** | 30 April 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Event ID** | 4624 — Successful Logon |
| **MITRE ATT&CK** | T1078 — Valid Accounts / T1021.001 — RDP |
| **Severity** | Medium — High (depends on source) |
| **Status** | Investigated — Simulated Attack (Lab) |

---

## 1. Alert Description

Splunk detected multiple successful login events (Event ID 4624) with Logon Type 2 (Interactive) on host `JIMIL-JOSHI`. A total of **4 login events** were recorded for account `hp` between 09:54 and 10:09 on 30/04/2026.

In a real SOC environment, monitoring Event ID 4624 is critical because:
- RDP logins (Logon Type 10) from unknown IPs indicate remote access attacks
- Interactive logins (Logon Type 2) outside business hours are suspicious
- Successful logins after multiple failures (4625) may indicate successful brute force

---

## 2. Detection Query Used

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4624
| where Logon_Type=2
| stats count by Account_Name, ComputerName, Logon_Type
| sort -count
```

---

## 3. Findings

| Account | Computer | Logon Type | Count |
|---|---|---|---|
| hp | JIMIL-JOSHI | 2 (Interactive) | 4 |
| JIMIL-JOSHI$ | JIMIL-JOSHI | 2 (Interactive) | 4 |

- Account `hp` had **4 successful interactive logins**
- Account `JIMIL-JOSHI$` is machine account — normal system behavior
- All logins from same machine — no external RDP detected
- Logon Type 2 = local interactive login (keyboard/screen)

---

## 4. Logon Type Reference

| Logon Type | Description | Risk Level |
|---|---|---|
| 2 | Interactive — local login | Low — Medium |
| 3 | Network — file share etc | Medium |
| 10 | RemoteInteractive — RDP | High |
| 11 | CachedInteractive | Medium |

---

## 5. Timeline of Events

| Time | Event |
|---|---|
| 09:54:00 | First successful login detected |
| 10:09:00 | Last successful login recorded |
| After lab | RDP disabled on machine |

---

## 6. Analysis

Event ID 4624 is one of the **most important events** a SOC analyst monitors because:

- It confirms **who logged in, when and how**
- RDP logins (Type 10) from external IPs are a major red flag
- Logins after hours may indicate compromised credentials
- Correlating 4625 (failed) → 4624 (success) can reveal successful brute force

**Key SOC investigation steps for 4624:**
1. Check Logon Type — is it RDP (10)?
2. Check Source IP — is it internal or external?
3. Check time — is it business hours?
4. Cross reference with 4625 — were there failed attempts before?

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Valid Accounts | T1078 |
| Lateral Movement | Remote Desktop Protocol | T1021.001 |
| Persistence | Valid Accounts | T1078.003 |

---

## 8. Conclusion

Splunk successfully detected all interactive login events on the machine. The SPL query filtered by Logon Type 2 and showed account names, computer names and login counts — giving full visibility into who logged in and when.

**Verdict: True Positive — Interactive Login Activity Detected ✅**

---

## 9. Recommendations

- Always monitor for Logon Type **10 (RDP)** from external IPs
- Set Splunk alert for RDP logins outside business hours
- Correlate Event ID 4624 with 4625 — success after failures = brute force
- Disable RDP when not needed — reduces attack surface
- Enable Network Level Authentication (NLA) for RDP

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/09_rdp_raw_events.png` | Raw Event ID 4624 in Splunk |
| `screenshots/10_rdp_stats_table.png` | Stats table showing login counts by account |
