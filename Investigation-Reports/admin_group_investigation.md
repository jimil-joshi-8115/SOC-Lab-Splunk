# 🔍 Investigation Report — User Added to Administrators Group

## Overview

| Field | Details |
|---|---|
| **Date** | 29 April 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Event ID** | 4732 — Member Added to Security Group |
| **MITRE ATT&CK** | T1098 — Account Manipulation |
| **Severity** | Critical |
| **Status** | Investigated — Simulated Attack (Lab) |

---

## 1. Alert Description

Splunk detected a user being added to the local Administrators group (Event ID 4732) on host `JIMIL-JOSHI`. Account `hp` performed this action multiple times between 09:31 and 09:35 on 29/04/2026.

In a real SOC environment, adding a user to the Administrators group is a **Critical severity** alert as it indicates:
- Privilege escalation attempt
- Attacker gaining admin rights on compromised system
- Persistence through elevated account access

---

## 2. Detection Query Used

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4732
| table _time, Account_Name, ComputerName, Security_ID, Member_Security_ID
```

---

## 3. Findings

| Time | Performed By | Computer | Action |
|---|---|---|---|
| 29/04/2026 09:31:50 | hp | JIMIL-JOSHI | User added to Administrators |
| 29/04/2026 09:32:09 | hp | JIMIL-JOSHI | User added to Administrators |
| 29/04/2026 09:35:34 | hp | JIMIL-JOSHI | User added to Administrators |
| 29/04/2026 09:35:43 | hp | JIMIL-JOSHI | User added to Administrators |

- Total of **5 events** detected
- All performed by account `hp` on `JIMIL-JOSHI`
- Multiple Security IDs visible — confirms group membership changes

---

## 4. Timeline of Events

| Time | Event |
|---|---|
| 09:31:50 | First group membership change detected |
| 09:35:43 | Last group membership change detected |
| After detection | Test user removed from Administrators group and deleted |

---

## 5. Analysis

Event ID 4732 is generated every time a user is added to a security-enabled local group. When the target group is **Administrators**, this is extremely suspicious because:

- Gives attacker **full control** over the machine
- Can install malware, disable security tools, exfiltrate data
- Admin rights allow attacker to cover tracks
- Often done right after initial compromise

**This is a classic Privilege Escalation technique** used by attackers to move from a low privilege user to full admin control.

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Privilege Escalation | Account Manipulation | T1098 |
| Persistence | Account Manipulation | T1098 |

---

## 7. Conclusion

Splunk successfully detected the privilege escalation simulation. The SPL query identified the account performing the action, the machine it occurred on, and full Security ID details — giving a SOC analyst complete visibility into the attack.

**Verdict: True Positive — Privilege Escalation Detected ✅**

---

## 8. Recommendations

- Set Splunk alert to trigger **immediately** on any Event ID 4732 targeting Administrators group
- Investigate **who** added the user and **why**
- Cross reference with Event ID 4720 (new user created) — attacker may have created user then escalated
- Review all accounts currently in Administrators group regularly
- Apply principle of least privilege — limit who can modify group memberships

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/07_admin_group_raw_events.png` | Raw Event ID 4732 in Splunk |
| `screenshots/08_admin_group_security_id.png` | Table showing Security IDs and details |
