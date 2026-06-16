# 🔍 Investigation Report — Insider Threat Detected

## Overview

| Field | Details |
|---|---|
| **Report ID** | IR-2026-002 |
| **Date** | 15 June 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Scenario** | Insider Threat Simulation |
| **MITRE ATT&CK** | T1136 / T1098 / T1070.001 |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ TRUE POSITIVE — Insider Threat Confirmed |

---

## 1. Scenario Description

An insider threat scenario was simulated where a malicious employee:
1. Created a backdoor user account (`insider`)
2. Added the account to Administrators group
3. Cleared Security logs to destroy evidence

This represents a **complete insider threat attack chain** — one of the most dangerous threats organizations face.

---

## 2. Detection Query Used

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

## 3. Findings

| Attack Stage | Account | Computer | Count |
|---|---|---|---|
| 1-New User Created | hp | JIMIL-JOSHI | 1 |
| 1-New User Created | insider | JIMIL-JOSHI | 1 🔴 |
| 2-Added to Admins | - | JIMIL-JOSHI | 2 |
| 2-Added to Admins | hp | JIMIL-JOSHI | 2 🔴 |
| 4-Log Clearing | hp | JIMIL-JOSHI | 1 🔴 |

---

## 4. Attack Timeline

```
INSIDER THREAT ATTACK CHAIN:
──────────────────────────────────────────
Step 1: Account 'hp' created user 'insider'
        → Event ID 4720 ✅ DETECTED

Step 2: Account 'hp' added 'insider' to Admins
        → Event ID 4732 ✅ DETECTED

Step 3: Insider had full admin access
        → Privilege Escalation confirmed!

Step 4: Account 'hp' cleared Security logs
        → Event ID 1102 ✅ DETECTED
        → Tried to cover tracks!
──────────────────────────────────────────
VERDICT: INSIDER THREAT CONFIRMED! 🔴
```

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Persistence | Create Account | T1136 |
| Persistence | Local Account | T1136.001 |
| Privilege Escalation | Account Manipulation | T1098 |
| Defense Evasion | Indicator Removal | T1070 |
| Defense Evasion | Clear Windows Event Logs | T1070.001 |

---

## 6. Verdict

**TRUE POSITIVE — Insider Threat Confirmed ✅**

Account `hp` on host `JIMIL-JOSHI` performed a complete insider threat attack chain including backdoor account creation, privilege escalation and evidence destruction.

---

## 7. Recommendations

- 🔴 Immediately disable account `insider`
- 🔴 Reset password for account `hp`
- 🔴 Escalate to SOC L2 for full forensic investigation
- 🟡 Review all actions performed by `insider` account
- 🟡 Check for any data exfiltration
- 🟢 Enable account creation alerts
- 🟢 Implement privileged account monitoring

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/insider_threat_detection.png` | Splunk correlation query showing full attack chain |
