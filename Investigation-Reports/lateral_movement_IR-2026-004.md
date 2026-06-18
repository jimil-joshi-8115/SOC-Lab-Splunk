# 🔍 Investigation Report — Lateral Movement Detected

## Overview

| Field | Details |
|---|---|
| **Report ID** | IR-2026-004 |
| **Date** | 18 June 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Scenario** | Lateral Movement Simulation |
| **MITRE ATT&CK** | T1021 / T1021.002 / T1078 |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ TRUE POSITIVE — Lateral Movement Technique Confirmed |

---

## 1. Scenario Description

A lateral movement scenario was simulated where an attacker who has already compromised one account attempts to move across the network using:
1. Windows admin shares (`\\computer\C$`, `\\computer\ADMIN$`) to access remote file systems
2. WMI (Windows Management Instrumentation) to remotely execute commands

This mirrors real-world post-exploitation tooling such as Impacket's `wmiexec.py` and PsExec, both commonly used by attackers and red teams to move between systems without dropping malware files ("living off the land").

---

## 2. Detection Queries Used

### Query 1 — Network Logon Detection
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4624
| where Logon_Type=3
| table _time, Account_Name, ComputerName, Logon_Type, Source_Network_Address
| sort -_time
```

### Query 2 — WMI Remote Execution Detection
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*wmic*" OR Process_Command_Line="*node*"
| table _time, Account_Name, New_Process_Name, Process_Command_Line
| sort -_time
```

### Query 3 — Logon Type Baseline (Behavioral Anomaly)
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4624
| stats count by Account_Name, Logon_Type, ComputerName
| sort Account_Name
```

---

## 3. Findings

### Network Logon Events (Logon Type 3)
| Time | Account | Computer | Logon Type | Source IP |
|---|---|---|---|---|
| 09:31:33 | hp | JIMIL-JOSHI | 3 (Network) 🔴 | 127.0.0.1 |
| 09:31:29 | hp | JIMIL-JOSHI | 3 (Network) 🔴 | 127.0.0.1 |

### WMI Remote Execution
| Time | Account | Process | Command |
|---|---|---|---|
| 09:31:36 | hp | WMIC.exe | `wmic /node:127.0.0.1 process call create "cmd.exe /c whoami"` |

### Logon Type Baseline for Account `hp`
| Account | Logon Type | Computer | Count |
|---|---|---|---|
| hp | 2 (Interactive — normal) | JIMIL-JOSHI | 4 |
| hp | 3 (Network — abnormal) 🔴 | JIMIL-JOSHI | 2 |

---

## 4. Behavioral Analysis

Account `hp`'s established baseline is **Interactive logon (Type 2)** — the expected pattern for a user logging into their own workstation. The appearance of **Network logon (Type 3)** events, occurring at the exact time admin share access commands (`net use \\127.0.0.1\C$`) were executed, represents a deviation from baseline behavior consistent with lateral movement.

---

## 5. Attack Timeline

```
LATERAL MOVEMENT ATTACK CHAIN:
──────────────────────────────────────────
Step 1: Admin share accessed via net use \\127.0.0.1\C$
        → Generated Network Logon (Type 3) — Event 4624 ✅

Step 2: ADMIN$ share accessed (PsExec-style technique)
        → Additional Network Logon (Type 3) — Event 4624 ✅

Step 3: WMI remote command execution
        → wmic /node:127.0.0.1 process call create "whoami"
        → Event 4688 ✅ DETECTED
──────────────────────────────────────────
VERDICT: LATERAL MOVEMENT TECHNIQUE CONFIRMED! 🔴
```

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Lateral Movement | Remote Services | T1021 |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 |
| Lateral Movement | Windows Management Instrumentation | T1047 |
| Initial Access / Persistence | Valid Accounts | T1078 |

---

## 7. Verdict

**✅ TRUE POSITIVE — Lateral Movement Technique Confirmed**

The combination of admin share access (Network Logon Type 3) and WMI-based remote process execution is a well-documented lateral movement pattern used by both real attackers and penetration testing tools. The behavioral deviation from account `hp`'s normal Interactive logon baseline strengthens this finding.

---

## 8. Recommendations

- 🔴 Investigate source and destination of all admin share access on the network
- 🔴 Restrict use of default admin shares (C$, ADMIN$) where not required
- 🔴 Escalate to SOC L2 to check for further lateral movement to other hosts
- 🟡 Enable WMI activity logging/auditing organization-wide
- 🟡 Implement network segmentation to limit lateral movement paths
- 🟢 Create a Splunk alert for Logon Type 3 combined with WMI process creation
- 🟢 Deploy Sysmon Event ID 1 for enhanced process command-line visibility
- 🟢 Consider disabling WMI remote execution for non-administrative accounts

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/lateral_movement_network_logon.png` | Network Logon (Type 3) detected — 2 events |
| `screenshots/lateral_movement_wmi_execution.png` | WMI remote process execution detected |
| `screenshots/lateral_movement_logon_baseline.png` | Logon type baseline showing behavioral anomaly |
