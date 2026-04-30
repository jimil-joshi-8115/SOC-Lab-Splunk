# 🔍 Investigation Report — Suspicious PowerShell Activity Detected

## Overview

| Field | Details |
|---|---|
| **Date** | 30 April 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Event ID** | 4104 — PowerShell Script Block Logging |
| **MITRE ATT&CK** | T1059.001 — PowerShell |
| **Severity** | High |
| **Status** | Investigated — Simulated Attack (Lab) |

---

## 1. Alert Description

Splunk detected multiple PowerShell script block events (Event ID 4104) on host `JIMIL-JOSHI`. A total of **20 PowerShell events** were recorded between 10:50 and 11:05 on 30/04/2026. Several suspicious reconnaissance commands were detected including `net localgroup administrators` and `Get-LocalUser`.

In a real SOC environment, PowerShell activity is **High severity** because:
- Attackers use PowerShell for reconnaissance, lateral movement and malware execution
- PowerShell can download and execute malicious code in memory
- Many malware families use PowerShell as their primary attack tool

---

## 2. Detection Query Used

```spl
index=main EventCode=4104
| table _time, ComputerName, Message
| sort -_time
```

---

## 3. Suspicious Commands Detected

| Time | Computer | Command | Risk |
|---|---|---|---|
| 11:02:51 | JIMIL-JOSHI | `net localgroup administrators` | 🔴 High |
| 11:02:48 | JIMIL-JOSHI | `Get-LocalUser` | 🟡 Medium |
| 11:02:47 | JIMIL-JOSHI | `Get-Process` | 🟡 Medium |
| 11:02:47 | JIMIL-JOSHI | `net user` | 🟡 Medium |
| 11:02:47 | JIMIL-JOSHI | `whoami` | 🟡 Medium |
| 11:02:47 | JIMIL-JOSHI | `ipconfig` | 🟡 Medium |

---

## 4. Timeline of Events

| Time | Event |
|---|---|
| 10:50:18 | First PowerShell event detected |
| 11:02:47 | Reconnaissance commands begin |
| 11:02:51 | `net localgroup administrators` executed |
| 11:05:18 | Last PowerShell event recorded |

---

## 5. Analysis

Event ID 4104 captures every PowerShell command executed on the machine. The following commands are highly suspicious in a SOC investigation:

**`net localgroup administrators`**
- Lists all members of the local Administrators group
- Attackers run this to identify privileged accounts to target
- Classic post-exploitation reconnaissance command

**`whoami`**
- Identifies current user context
- First command attackers run after gaining access

**`Get-LocalUser`**
- Lists all local user accounts
- Used to identify accounts for lateral movement or privilege escalation

**`net user`**
- Lists all user accounts on the machine
- Standard attacker reconnaissance command

These commands together form a **complete reconnaissance pattern** — exactly what an attacker would do after gaining initial access to a machine.

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Execution | PowerShell | T1059.001 |
| Discovery | Account Discovery | T1087 |
| Discovery | Local Account Discovery | T1087.001 |
| Discovery | Process Discovery | T1057 |
| Discovery | System Network Configuration Discovery | T1016 |

---

## 7. Conclusion

Splunk successfully detected suspicious PowerShell activity including multiple reconnaissance commands. The SPL query captured all PowerShell script blocks and revealed exact commands executed — giving a SOC analyst complete visibility into attacker activity.

**Verdict: True Positive — Suspicious PowerShell Reconnaissance Detected ✅**

---

## 8. Recommendations

- Enable PowerShell Script Block Logging on all endpoints permanently
- Set Splunk alert for high risk PowerShell keywords:
  - `Invoke-Expression`, `DownloadString`, `bypass`, `EncodedCommand`
  - `net localgroup administrators`, `whoami`, `Get-LocalUser`
- Consider enabling **PowerShell Constrained Language Mode**
- Monitor for PowerShell running from unusual locations
- Correlate PowerShell events with other suspicious activity

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/11_powershell_raw_events.png` | 20 raw Event ID 4104 events in Splunk |
| `screenshots/12_powershell_commands_detected.png` | Table showing actual commands detected |
