# 🔍 Investigation Report — Advanced Threat Detection Using Correlation Rules

## Overview

| Field | Details |
|---|---|
| **Date** | 07 May 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Technique** | Multi-Event Correlation Analysis |
| **Total Rules** | 3 |
| **Threats Detected** | 3 Critical/High |
| **Purpose** | Advanced attack pattern detection |

---

## 1. What Are Correlation Rules?

Correlation rules detect **complex attack patterns** by connecting multiple events together. A single event might look innocent — but when combined with other events, it reveals a full attack chain.

**Example:**
- 1 failed login = normal ✅
- 10 failed logins = suspicious 🟡
- 10 failed logins + 1 success = **brute force attack!** 🔴

---

## 2. Correlation Rule 1 — Brute Force Then Successful Login

### Query
```spl
index=main sourcetype="WinEventLog:Security"
| eval event_type=case(EventCode="4625","Failed Login", EventCode="4624","Successful Login")
| where isnotnull(event_type)
| stats count(eval(EventCode="4625")) as failed_count, count(eval(EventCode="4624")) as success_count by Account_Name, ComputerName
| where failed_count >= 3 AND success_count >= 1
| eval risk="HIGH — Possible Successful Brute Force!"
| table Account_Name, ComputerName, failed_count, success_count, risk
```

### Findings

| Account | Computer | Failed | Success | Risk |
|---|---|---|---|---|
| - | JIMIL-JOSHI | 13 | 2 | 🔴 HIGH |
| JIMIL-JOSHI$ | JIMIL-JOSHI | 5 | 244 | 🔴 HIGH |
| hp | JIMIL-JOSHI | 18 | 12 | 🔴 HIGH |

### Analysis
Account `hp` had **18 failed logins** followed by **12 successful logins** — strong indicator of successful brute force attack. The attacker tried multiple passwords and eventually gained access.

### MITRE ATT&CK
- T1110 — Brute Force
- T1078 — Valid Accounts

---

## 3. Correlation Rule 2 — New User Created Then Added to Admins

### Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4720 OR EventCode=4732
| stats count(eval(EventCode="4720")) as new_user, count(eval(EventCode="4732")) as added_to_admin by Account_Name, ComputerName
| where new_user >= 1 AND added_to_admin >= 1
| eval risk="CRITICAL — Backdoor Admin Account Created!"
| table Account_Name, ComputerName, new_user, added_to_admin, risk
```

### Findings

| Account | Computer | New Users | Added to Admin | Risk |
|---|---|---|---|---|
| hp | JIMIL-JOSHI | 2 | 3 | 🔴 CRITICAL |

### Analysis
Account `hp` created **2 new user accounts** AND added **3 accounts to Administrators group** — classic attacker persistence technique. The attacker created backdoor accounts with admin privileges to maintain access even if their original account is discovered.

### MITRE ATT&CK
- T1136 — Create Account
- T1098 — Account Manipulation
- T1078 — Valid Accounts

---

## 4. Correlation Rule 3 — Attack Then Evidence Destroyed

### Query
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625 OR EventCode=1102
| stats count(eval(EventCode="4625")) as failed_logins, count(eval(EventCode="1102")) as log_cleared by Account_Name, ComputerName
| where failed_logins >= 3 AND log_cleared >= 1
| eval risk="CRITICAL — Attack then Evidence Destroyed!"
| table Account_Name, ComputerName, failed_logins, log_cleared, risk
```

### Findings

| Account | Computer | Failed Logins | Logs Cleared | Risk |
|---|---|---|---|---|
| hp | JIMIL-JOSHI | 18 | 3 | 🔴 CRITICAL |

### Analysis
Account `hp` had **18 failed login attempts** AND cleared Windows Security logs **3 times** — this is a complete attack chain. The attacker attempted brute force and then tried to destroy evidence by clearing logs. This is the most dangerous pattern as it shows both attack and anti-forensics activity.

### MITRE ATT&CK
- T1110 — Brute Force
- T1070.001 — Clear Windows Event Logs

---

## 5. Attack Chain Visualization

```
ATTACKER TIMELINE:
─────────────────────────────────────────────────────
Step 1: Brute Force (18 failed logins) → EventCode 4625
         ↓
Step 2: Successful Login (12 times) → EventCode 4624
         ↓
Step 3: Created backdoor users (2) → EventCode 4720
         ↓
Step 4: Added users to Admins (3) → EventCode 4732
         ↓
Step 5: Cleared Security logs (3 times) → EventCode 1102
─────────────────────────────────────────────────────
RESULT: Full compromise with persistence and anti-forensics!
```

---

## 6. Why Correlation Rules Are Powerful

| Single Event Detection | Correlation Detection |
|---|---|
| Detects one event at a time | Detects full attack chains |
| Many false positives | Fewer false positives |
| Misses complex attacks | Catches sophisticated attacks |
| Basic SOC skill | Advanced SOC skill |

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force | T1110 |
| Initial Access | Valid Accounts | T1078 |
| Persistence | Create Account | T1136 |
| Persistence | Account Manipulation | T1098 |
| Defense Evasion | Clear Windows Event Logs | T1070.001 |

---

## 8. Conclusion

All 3 correlation rules successfully detected complex attack patterns on host `JIMIL-JOSHI`. The rules connected multiple events to reveal complete attack chains — from initial brute force through persistence to evidence destruction.

**Verdict: True Positive — Complete Attack Chain Detected ✅**

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/38_correlation_brute_force.png` | Brute force then successful login detected |
| `screenshots/39_correlation_backdoor_admin.png` | Backdoor admin account creation detected |
| `screenshots/40_correlation_attack_evidence.png` | Attack then evidence destruction detected |
