# 🔍 Investigation Report — Suspicious Process Creation Detected

## Overview

| Field | Details |
|---|---|
| **Date** | 01 May 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Event ID** | 4688 — New Process Created |
| **MITRE ATT&CK** | T1059 — Command and Scripting Interpreter |
| **Severity** | High |
| **Status** | Investigated — Simulated Attack (Lab) |

---

## 1. Alert Description

Splunk detected multiple suspicious process creation events (Event ID 4688) on host `JIMIL-JOSHI`. A total of **613 process creation events** were logged, with **4 high risk processes** identified including `whoami.exe` and `net.exe` running reconnaissance commands.

In a real SOC environment, process creation monitoring is **critical** because:
- Attackers use built-in Windows tools (Living off the Land)
- Malicious processes leave traces in Event ID 4688
- Command line logging reveals exact attacker commands

---

## 2. Detection Queries Used

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*cmd.exe*" OR New_Process_Name="*net.exe*" OR New_Process_Name="*whoami*"
| table _time, Account_Name, New_Process_Name, Process_Command_Line
| sort -_time
| head 10
```

---

## 3. Suspicious Processes Detected

| Time | Account | Process | Command | Risk |
|---|---|---|---|---|
| 17:57:39 | JIMIL-JOSHI$ | cmd.exe | `cmd.exe /c "ver"` | 🟡 Medium |
| 17:56:26 | hp | net.exe | `net localgroup administrators` | 🔴 High |
| 17:55:54 | hp | whoami.exe | `whoami` | 🔴 High |
| 17:55:43 | hp | cmd.exe | `cmd.exe` | 🟡 Medium |

---

## 4. Top Processes by Count

| Process | Count |
|---|---|
| splunk-optimize.exe | 401 |
| splunk-powershell.exe | 14 |
| python3.13.exe | 14 |
| whoami.exe | 1 |
| net.exe | 1 |

---

## 5. Timeline of Events

| Time | Event |
|---|---|
| 17:47:10 | Process creation logging begins |
| 17:55:43 | `cmd.exe` launched by `hp` |
| 17:55:54 | `whoami.exe` executed — recon begins |
| 17:56:26 | `net.exe` runs `net localgroup administrators` |
| 17:57:39 | `cmd.exe /c "ver"` executed |

---

## 6. Analysis

Event ID 4688 with command line logging enabled gives SOC analysts **complete visibility** into every process and command run on the machine.

**Key suspicious indicators found:**

**`whoami`**
- First command attackers run after compromise
- Confirms current user context and privileges

**`net localgroup administrators`**
- Lists all members of Administrators group
- Classic privilege escalation reconnaissance
- Attacker checks if they have admin rights

**Living off the Land (LOL) Technique:**
- Attackers use built-in Windows tools like `cmd.exe`, `net.exe`, `whoami.exe`
- These tools are already on every Windows machine
- Hard to detect without proper logging
- Event ID 4688 with command line logging catches them!

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Execution | Command and Scripting Interpreter | T1059 |
| Execution | Windows Command Shell | T1059.003 |
| Discovery | Account Discovery | T1087 |
| Discovery | Local Account Discovery | T1087.001 |
| Discovery | System Owner/User Discovery | T1033 |

---

## 8. Conclusion

Splunk successfully detected suspicious process creation events including reconnaissance commands run by account `hp` on host `JIMIL-JOSHI`. Command line logging revealed exact attacker commands — giving complete visibility into post-exploitation activity.

**Verdict: True Positive — Suspicious Process Creation Detected ✅**

---

## 9. Recommendations

- Enable Process Creation logging and Command Line logging on all endpoints
- Alert on high risk processes: `whoami.exe`, `net.exe`, `ipconfig.exe`, `systeminfo.exe`
- Correlate process creation with parent process — suspicious if spawned from `Word.exe` or `Excel.exe`
- Look for processes running from unusual paths like `%TEMP%` or `AppData`
- Consider deploying Sysmon for even more detailed process logging

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/15_process_creation_filtered.png` | Filtered suspicious process events |
| `screenshots/16_process_creation_stats.png` | Stats table of all processes |
| `screenshots/17_process_creation_cmdline.png` | Command line details of suspicious processes |
