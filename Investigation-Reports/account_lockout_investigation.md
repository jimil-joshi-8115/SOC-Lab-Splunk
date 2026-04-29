# 🔍 Investigation Report — Account Lockout Detected

## Overview

| Field | Details |
|---|---|
| **Date** | 29 April 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Event ID** | 4740 — Account Locked Out |
| **MITRE ATT&CK** | T1110 — Brute Force |
| **Severity** | High |
| **Status** | Investigated — Simulated Attack (Lab) |

---

## 1. Alert Description

Splunk detected an account lockout event (Event ID 4740) on host `JIMIL-JOSHI` at 08:58:06 on 29/04/2026. Account `hp` was locked out after multiple consecutive failed login attempts. The lockout was triggered from the same machine `JIMIL-JOSHI`.

In a real SOC environment, account lockouts are **High severity** alerts as they may indicate:
- Active brute force attack in progress
- Credential stuffing attack
- Compromised automated system trying old credentials

---

## 2. Detection Query Used

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4740
| table _time, Account_Name, ComputerName, Caller_Computer_Name
```

---

## 3. Findings

| Time | Locked Account | Computer | Locked By |
|---|---|---|---|
| 29/04/2026 08:58:06 | hp | JIMIL-JOSHI | JIMIL-JOSHI |

- Account `hp` was locked out on host `JIMIL-JOSHI`
- Lockout triggered from same machine — indicates local brute force
- Account lockout threshold was set to 3 failed attempts

---

## 4. Timeline of Events

| Time | Event |
|---|---|
| 08:58:06 | Account `hp` locked out (Event ID 4740) |
| 08:58:06 | Splunk ingested and detected the event |
| After detection | Account unlocked — policy reset to 0 |

---

## 5. Analysis

Event ID 4740 is generated when a Windows account gets locked due to too many failed login attempts. This is a **critical SOC alert** because:

- It confirms an active brute force attempt reached lockout threshold
- The attacker was trying to guess the password repeatedly
- Account lockout prevents further attempts but also causes **denial of service** to legitimate user
- SOC analyst must investigate source of failed attempts immediately

**Key difference from Event ID 4625:**
- 4625 = Failed login attempt (may be accidental)
- 4740 = Account fully locked out (almost always suspicious)

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force | T1110 |
| Credential Access | Password Guessing | T1110.001 |
| Impact | Account Access Removal | T1531 |

---

## 7. Conclusion

Splunk successfully detected the account lockout event. The SPL query identified the locked account, the machine it occurred on, and the exact timestamp — giving a SOC analyst everything needed to investigate and respond quickly.

**Verdict: True Positive — Account Lockout Detected ✅**

---

## 8. Recommendations

- Always correlate Event ID 4740 with 4625 — look for failed logins just before lockout
- Check if lockout came from **different machine** — indicates network brute force
- If lockout from **same machine** — may indicate malware or local attacker
- Set Splunk alert to trigger **immediately** on any Event ID 4740
- Investigate source IP and username immediately in real environment

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/05_lockout_raw_event.png` | Raw Event ID 4740 in Splunk |
| `screenshots/06_lockout_table.png` | Table showing locked account details |
