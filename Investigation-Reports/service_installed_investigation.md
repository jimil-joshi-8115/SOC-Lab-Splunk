# 🔍 Investigation Report — Malicious Service Installed

## Overview

| Field | Details |
|---|---|
| **Date** | 03 May 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Event ID** | 7045 — New Service Installed |
| **MITRE ATT&CK** | T1543.003 — Windows Service |
| **Severity** | Critical |
| **Status** | Investigated — Simulated Attack (Lab) |

---

## 1. Alert Description

Splunk detected **1 service installation event** (Event ID 7045) on host `JIMIL-JOSHI` at 10:24:39 on 03/05/2026. A suspicious service named **"FakeService"** was installed with `cmd.exe /c whoami` as the service binary — a clear indicator of malicious activity.

In a real SOC environment, new service installation is **Critical severity** because:
- Services run automatically on system boot — guaranteed persistence
- Services run with SYSTEM privileges by default
- Attackers use services to maintain long-term access
- Malicious services can survive user logoff and system restarts

---

## 2. Detection Query Used

```spl
index=main sourcetype="WinEventLog:System" EventCode=7045
| table _time, ComputerName, Message
| sort -_time
```

---

## 3. Findings

| Field | Value | Risk |
|---|---|---|
| Service Name | FakeService | 🔴 Suspicious name |
| Service File | `cmd.exe /c whoami` | 🔴 Critical — cmd.exe as service binary |
| Service Type | user mode service | 🟡 Medium |
| Start Type | auto start | 🔴 Persistence confirmed |
| Service Account | LocalSystem | 🔴 Highest privileges |

---

## 4. Timeline of Events

| Time | Event |
|---|---|
| 10:24:39 | `FakeService` installed on `JIMIL-JOSHI` |
| 10:24:39 | Splunk detected Event ID 7045 |
| After detection | Service deleted — `sc delete FakeService` |

---

## 5. Analysis

Event ID 7045 is one of the **most critical persistence events** a SOC analyst monitors:

**Why This Service is Malicious:**

**Service Binary = `cmd.exe /c whoami`**
- No legitimate service uses `cmd.exe` as its binary
- `whoami` is a classic attacker recon command
- This is a textbook malicious service installation

**Start Type = Auto Start**
- Service starts automatically every time Windows boots
- Attacker maintains access even after reboots
- Classic persistence technique

**Account = LocalSystem**
- Highest privilege level on Windows
- Full access to all system resources
- Attackers target SYSTEM level for maximum control

**Service Name = FakeService**
- In real attacks, names mimic legitimate services
- Examples: `WindowsDefender`, `MicrosoftUpdate`, `SvcHost`
- Makes detection harder for untrained analysts

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Persistence | Create or Modify System Process | T1543 |
| Persistence | Windows Service | T1543.003 |
| Privilege Escalation | Create or Modify System Process | T1543 |

---

## 7. Conclusion

Splunk successfully detected the malicious service installation via Event ID 7045. The detection provided complete service details including name, binary path, start type and account — giving a SOC analyst everything needed to confirm malicious persistence.

**Verdict: True Positive — Malicious Service Installation Detected ✅**

---

## 8. Recommendations

- Alert immediately on any Event ID 7045
- Investigate service binary path — flag any using `cmd.exe`, `powershell.exe` or paths in `%TEMP%` or `AppData`
- Check service account — SYSTEM level services need extra scrutiny
- Maintain a baseline of known good services — alert on new additions
- Use `sc query` or `Get-Service` regularly to audit running services
- Consider application whitelisting to block unauthorized service binaries

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/24_service_installed_raw.png` | Raw Event ID 7045 in Splunk |
| `screenshots/25_service_installed_details.png` | Full service details — FakeService with cmd.exe binary |
