# 🎯 Scenario 03 — Lateral Movement Detection

## Scenario Overview

| Field | Details |
|---|---|
| **Scenario Name** | Lateral Movement |
| **Difficulty** | High |
| **Date** | 18 June 2026 |
| **Analyst** | Jimil Joshi |
| **Tools Used** | Splunk Enterprise, Windows Event Logs |
| **MITRE ATT&CK** | T1021, T1021.002, T1047, T1078 |
| **Severity** | 🔴 Critical |

---

## Scenario Story

> An attacker has already compromised one machine using stolen credentials. They now attempt to move across the network to reach more valuable systems — using Windows admin shares and WMI remote execution, two classic "living off the land" lateral movement techniques. As SOC L1 analyst, detect this movement using Splunk!

---

## Attack Chain Simulated

```
Step 1 → Access C$ admin share using stolen credentials
Step 2 → Access ADMIN$ share (PsExec-style technique)
Step 3 → Execute remote command via WMI
Step 4 → Enumerate active network sessions
```

---

## Commands Used to Simulate

```cmd
REM Step 1 - Access admin share
net use \\127.0.0.1\C$ /user:hp

REM Step 2 - Access ADMIN$ share
net use \\127.0.0.1\ADMIN$ /user:hp

REM Step 3 - Remote command execution via WMI
wmic /node:127.0.0.1 process call create "cmd.exe /c whoami"

REM Step 4 - Enumerate sessions
net session
net use
```

---

## Detection Queries

### Network Logon Detection
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4624
| where Logon_Type=3
| table _time, Account_Name, ComputerName, Logon_Type, Source_Network_Address
| sort -_time
```

### WMI Remote Execution Detection
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*wmic*" OR Process_Command_Line="*node*"
| table _time, Account_Name, New_Process_Name, Process_Command_Line
| sort -_time
```

---

## Results

### Network Logon (Type 3)
| Time | Account | Computer | Logon Type | Source IP |
|---|---|---|---|---|
| 09:31:33 | hp | JIMIL-JOSHI | 3 (Network) 🔴 | 127.0.0.1 |
| 09:31:29 | hp | JIMIL-JOSHI | 3 (Network) 🔴 | 127.0.0.1 |

### WMI Remote Execution
| Time | Account | Process | Command |
|---|---|---|---|
| 09:31:36 | hp | WMIC.exe | `wmic /node:127.0.0.1 process call create "cmd.exe /c whoami"` |

### Behavioral Baseline
| Account | Logon Type | Count |
|---|---|---|
| hp | 2 (Interactive — normal) | 4 |
| hp | 3 (Network — abnormal) 🔴 | 2 |

---

## 🎯 Real SOC Insight — Behavioral Anomaly Detection

Account `hp`'s normal baseline is Interactive logon (Type 2). The sudden appearance of Network logon (Type 3) events — occurring at the exact moment admin share commands were run — represents a measurable deviation from baseline behavior. This is exactly how real SOC teams use behavioral analytics to spot lateral movement that a single static rule might miss.

---

## Verdict

**✅ TRUE POSITIVE — Lateral Movement Technique Confirmed**

The combination of admin share access (Network Logon) and WMI-based remote execution is a well-documented lateral movement pattern, consistent with tools like Impacket's wmiexec.py and PsExec.

---

## Files in This Scenario

| File | Description |
|---|---|
| `README.md` | This file — scenario overview |
| `screenshots/lateral_movement_network_logon.png` | Network Logon detection |
| `screenshots/lateral_movement_wmi_execution.png` | WMI remote execution detection |
| `screenshots/lateral_movement_logon_baseline.png` | Behavioral baseline comparison |

---

## Related Files

| File | Location |
|---|---|
| SPL Query | `SPL-Queries/lateral_movement_detection.spl` |
| Investigation Report | `Investigation-Reports/lateral_movement_IR-2026-004.md` |
| Incident Report | `Incident-Reports/IR-2026-004_Lateral_Movement.docx` |

---

## 📄 Full Investigation Report

📄 [IR-2026-004 — Lateral Movement Investigation](../../Investigation-Reports/lateral_movement_IR-2026-004.md)

---

## Screenshot

![Lateral Movement WMI Execution](screenshots/lateral_movement_wmi_execution.png)
