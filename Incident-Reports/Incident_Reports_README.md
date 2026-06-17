# 📁 Incident Reports

> Professional incident reports written in SOC analyst format — documenting attack findings, evidence, MITRE ATT&CK mapping, and recommended actions.

---

## 📋 What Is an Incident Report?

In a real SOC, after detecting a threat in the SIEM, the analyst writes a formal **Incident Report** documenting:

- ✅ What happened (attack chain)
- ✅ Who did it (affected accounts)
- ✅ When it happened (timeline)
- ✅ How it was detected (SPL queries + evidence)
- ✅ MITRE ATT&CK technique mapping
- ✅ Verdict — True Positive or False Positive
- ✅ Recommended actions for the security team

> **Note:** Reports are in `.docx` format. GitHub does not preview Word files — click the file and use the **Download** button to open in Microsoft Word.

---

## 🗂️ Reports Index

| Report ID | Scenario | Threat Type | MITRE | Severity | Verdict |
|---|---|---|---|---|---|
| [IR-2026-002](IR-2026-002_Insider_Threat.docx) | Insider Threat Detection | Insider Threat | T1136, T1098, T1070.001 | 🔴 Critical | TRUE POSITIVE |

---

## 📄 IR-2026-002 — Insider Threat Detection

**Date:** 15 June 2026
**Analyst:** Jimil Joshi
**Host:** JIMIL-JOSHI
**Affected Account:** hp
**Backdoor Account Created:** insider

### Attack Chain Detected

```
Step 1 → Account 'hp' created backdoor user 'insider'   [Event 4720] ✅
Step 2 → Account 'insider' added to Administrators       [Event 4732] ✅
Step 3 → Security logs cleared to destroy evidence       [Event 1102] ✅

VERDICT: INSIDER THREAT CONFIRMED 🔴 — Escalate to SOC L2
```

### MITRE ATT&CK

| Technique | Name | Tactic |
|---|---|---|
| T1136 | Create Account | Persistence |
| T1098 | Account Manipulation | Privilege Escalation |
| T1070.001 | Clear Windows Event Logs | Defense Evasion |

📄 [Download Full Report](IR-2026-002_Insider_Threat.docx)

---

*More incident reports will be added as scenarios are completed.*
