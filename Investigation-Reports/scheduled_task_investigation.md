# 🔍 Investigation Report — Suspicious Scheduled Task Created

## Overview

| Field | Details |
|---|---|
| **Date** | 03 May 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Event ID** | 4104 (Alternative) / 4698 (Ideal) |
| **MITRE ATT&CK** | T1053.005 — Scheduled Task |
| **Severity** | High |
| **Status** | Investigated — Simulated Attack (Lab) |

---

## 1. Alert Description

Splunk detected **27 PowerShell events** (Event ID 4104) containing scheduled task creation activity on host `JIMIL-JOSHI`. A suspicious scheduled task named **"WindowsUpdate"** was detected — a classic attacker technique of disguising malicious tasks with legitimate-looking names.

In a real SOC environment, scheduled task creation is **High severity** because:
- Attackers use scheduled tasks to maintain **persistent access**
- Tasks survive system reboots
- Tasks can execute malware automatically
- Attackers disguise tasks with legitimate names like "WindowsUpdate"

---

## 2. Detection Method

### Ideal Detection — Event ID 4698
Event ID 4698 is the native Windows event for scheduled task creation. This requires the **Task Scheduler Operational** log source to be configured in Splunk.

### Alternative Detection Used — Event ID 4104
Since Event ID 4698 was not available in this lab environment, **PowerShell Script Block Logging (Event ID 4104)** was used as an alternative detection method capturing the exact task creation command.

> **Note:** In a production SOC environment, both Event ID 4698 and 4104 should be monitored together for complete scheduled task detection coverage.

---

## 3. Detection Query Used

```spl
index=main EventCode=4104
| search Message="*schtasks*" OR Message="*ScheduledTask*" OR Message="*WindowsUpdate*"
| table _time, ComputerName, Message
| sort -_time
| head 20
```

---

## 4. Findings

| Time | Computer | Task Detected | Risk |
|---|---|---|---|
| 09:33:50 | JIMIL-JOSHI | `{$_.TaskName -eq "WindowsUpdate"}` | 🔴 High |
| 09:33:47 | JIMIL-JOSHI | Scheduled task script block execution | 🟡 Medium |

- **27 total events** detected on `JIMIL-JOSHI`
- Task name `WindowsUpdate` — disguised as legitimate Windows update task
- Task configured to run `cmd.exe /c whoami` on logon
- Task set to run as `System` — elevated privileges!

---

## 5. Timeline of Events

| Time | Event |
|---|---|
| 09:20:51 | First scheduled task related event detected |
| 09:33:47 | Task creation script block executed |
| 09:33:50 | `WindowsUpdate` task name detected in PowerShell logs |
| After detection | Fake task deleted — `schtasks /delete /tn "WindowsUpdate" /f` |

---

## 6. Analysis

Scheduled task persistence is one of the **most common attacker techniques**:

**Why Attackers Use Scheduled Tasks:**
- Survive system reboots — persistence guaranteed
- Run with SYSTEM privileges — no user interaction needed
- Easy to disguise with legitimate-looking names
- Built into every Windows system — no additional tools needed

**Red Flags in This Investigation:**
- Task name `WindowsUpdate` mimics legitimate Windows process
- Task runs `cmd.exe` — suspicious for a Windows update task
- Task triggered `onlogon` — executes every time user logs in
- Task runs as `System` — maximum privileges

**Living off the Land:**
Using `schtasks.exe` (built-in Windows tool) means no malware needed — harder to detect with traditional antivirus.

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Persistence | Scheduled Task/Job | T1053 |
| Persistence | Scheduled Task | T1053.005 |
| Privilege Escalation | Scheduled Task/Job | T1053 |
| Execution | Scheduled Task/Job | T1053 |

---

## 8. Conclusion

Splunk successfully detected the creation of a suspicious scheduled task disguised as "WindowsUpdate". PowerShell Script Block Logging captured the exact task name and creation activity — giving a SOC analyst complete visibility into the persistence attempt.

**Verdict: True Positive — Malicious Scheduled Task Detected ✅**

---

## 9. Recommendations

- Configure Task Scheduler Operational logs in Splunk for Event ID 4698
- Monitor both Event ID 4698 and 4104 for complete detection
- Alert on suspicious task names that mimic Windows processes
- Review all scheduled tasks regularly — look for unusual trigger conditions
- Alert on tasks running `cmd.exe`, `powershell.exe` or scripts from temp folders
- Restrict who can create scheduled tasks via Group Policy

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/22_scheduled_task_detected.png` | PowerShell events showing WindowsUpdate task detection |
| `screenshots/23_scheduled_task_stats.png` | Stats showing 27 events on JIMIL-JOSHI |
