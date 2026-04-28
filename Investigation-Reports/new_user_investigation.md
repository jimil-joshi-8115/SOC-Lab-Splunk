# 🔍 Investigation Report — Suspicious New User Account Created

## Overview

| Field | Details |
|---|---|
| **Date** | 28 April 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Event ID** | 4720 — User Account Created |
| **MITRE ATT&CK** | T1136 — Create Account |
| **Severity** | High |
| **Status** | Investigated — Simulated Attack (Lab) |

---

## 1. Alert Description

Splunk detected a new local user account creation (Event ID 4720) on host `JIMIL-JOSHI`. A new account named `hacker` was created by account `hp` at 17:26:51 on 28/04/2026.

In a real SOC environment, unauthorized account creation is a **High severity** alert as attackers commonly create backdoor accounts to maintain persistent access to a compromised machine.

---

## 2. Detection Query Used

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4720
| table _time, Account_Name, ComputerName, Security_ID
```

---

## 3. Findings

| Time | Account Created | Created By | Computer |
|---|---|---|---|
| 28/04/2026 17:26:51 | hacker | hp | JIMIL-JOSHI |

- Account `hacker` was created on host `JIMIL-JOSHI`
- Created by account `hp`
- This is a clear indicator of **persistence attempt** by an attacker

---

## 4. Timeline of Events

| Time | Event |
|---|---|
| 17:26:51 | New user account `hacker` created (Event ID 4720) |
| 17:26:51 | Splunk ingested and detected the event |
| After detection | Account deleted — threat contained |

---

## 5. Analysis

Event ID 4720 is generated every time a new local user account is created on Windows. This is a **critical event** to monitor in a SOC because:

- Attackers create local accounts to maintain **persistent access**
- Backdoor accounts survive reboots and password changes
- Often done after initial compromise to ensure continued access
- Account name `hacker` is clearly suspicious and not a legitimate system account

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Persistence | Create Account | T1136 |
| Persistence | Local Account | T1136.001 |

---

## 7. Conclusion

Splunk successfully detected the creation of a suspicious local user account. The SPL query identified the new account, the account that created it, and the exact timestamp — giving a SOC analyst everything needed to investigate and respond.

**Verdict: True Positive — Backdoor Account Creation Detected ✅**

---

## 8. Recommendations

- Set Splunk alert to trigger **immediately** on any Event ID 4720
- Investigate **who** created the account and **why**
- Cross reference with Event ID 4625 (failed logins) — attacker may have brute forced first then created account
- Enable Group Policy to restrict who can create local accounts
- Check for Event ID 4722 (account enabled) and 4723 (password change) after 4720

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/03_new_user_raw_event.png` | Raw Event ID 4720 in Splunk |
| `screenshots/04_new_user_table.png` | Table showing hacker account creation |
