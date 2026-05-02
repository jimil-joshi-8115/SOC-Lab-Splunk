# 🔍 Investigation Report — Windows Event Log Cleared

## Overview

| Field | Details |
|---|---|
| **Date** | 02 May 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Event ID** | 1102 — Audit Log Cleared |
| **MITRE ATT&CK** | T1070.001 — Indicator Removal: Clear Windows Event Logs |
| **Severity** | Critical |
| **Status** | Investigated — Simulated Attack (Lab) |

---

## 1. Alert Description

Splunk detected **2 log clearing events** (Event ID 1102) on host `JIMIL-JOSHI` at 15:29:36 and 15:29:38 on 02/05/2026. Account `hp` cleared the Windows Security audit log using `wevtutil cl Security` command.

In a real SOC environment, log clearing is **Critical severity** because:
- Attackers clear logs to **destroy evidence** of their activity
- Log clearing itself is evidence of malicious intent
- Indicates attacker had admin privileges on the machine
- May mean previous attack activity is now lost

---

## 2. Detection Query Used

```spl
index=main sourcetype="WinEventLog:Security" EventCode=1102
| table _time, ComputerName, Account_Name, Message
| sort -_time
```

---

## 3. Findings

| Time | Account | Computer | Action |
|---|---|---|---|
| 02/05/2026 15:29:36 | hp | JIMIL-JOSHI | The audit log was cleared |
| 02/05/2026 15:29:38 | hp | JIMIL-JOSHI | The audit log was cleared |

- Account `hp` cleared the Security audit log **twice**
- Security ID: `S-1-5-21-3249280887-4284458297-2517669470-1001`
- Domain: `JIMIL-JOSHI`
- Logon ID: `0x3EAD3`

---

## 4. Timeline of Events

| Time | Event |
|---|---|
| 15:29:36 | First log clearing event detected (Event ID 1102) |
| 15:29:38 | Second log clearing event detected (Event ID 1102) |
| After detection | Splunk retained all logs — evidence preserved ✅ |

---

## 5. Analysis

Event ID 1102 is one of the **most critical events** a SOC analyst can receive. Here is why:

**Why Attackers Clear Logs:**
- Remove evidence of brute force attempts (4625)
- Remove evidence of new accounts created (4720)
- Remove evidence of privilege escalation (4732)
- Remove evidence of malicious process execution (4688)
- Cover tracks before leaving the compromised system

**Key Insight:**
The fact that logs were cleared is **itself evidence of compromise**. A legitimate administrator rarely needs to clear Security logs. Any log clearing event should be treated as a **Critical incident** until proven otherwise.

**Why Splunk Still Has the Logs:**
- Splunk ingests logs in **real time** as they are created
- Even if Windows logs are cleared — Splunk already has copies
- This is why SIEM tools are critical — they preserve evidence attackers try to destroy!

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Defense Evasion | Indicator Removal | T1070 |
| Defense Evasion | Clear Windows Event Logs | T1070.001 |

---

## 7. Conclusion

Splunk successfully detected the Windows Security log clearing event. Even though the attacker cleared Windows logs, Splunk had already ingested and preserved all evidence. The SOC analyst can see exactly who cleared the logs, when and from which machine.

**Verdict: True Positive — Log Clearing / Evidence Destruction Detected ✅**

---

## 8. Recommendations

- Set Splunk alert to trigger **immediately** on any Event ID 1102
- Treat every log clearing event as **Critical** — investigate immediately
- Always forward logs to SIEM in real time — never rely on local Windows logs only
- Check what events occurred **just before** the log clearing — attacker may have been active
- Correlate 1102 with 4625, 4720, 4732, 4688 — look for attack pattern before clearing
- Restrict who can clear event logs using Group Policy

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/18_log_clearing_raw_events.png` | 2 raw Event ID 1102 events in Splunk |
| `screenshots/19_log_clearing_table.png` | Table showing "The audit log was cleared" with account details |
