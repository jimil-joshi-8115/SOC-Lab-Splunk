# 🔍 Investigation Report — Ransomware Behavior Detected

## Overview

| Field | Details |
|---|---|
| **Report ID** | IR-2026-003 |
| **Date** | 17 June 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Scenario** | Ransomware Simulation |
| **MITRE ATT&CK** | T1486 / T1490 |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ TRUE POSITIVE — Ransomware Behavior Confirmed |

---

## 1. Scenario Description

A ransomware simulation was performed on host `JIMIL-JOSHI` to practice detecting common ransomware behaviors:
1. Test files created and renamed with a `.locked` extension (simulating file encryption)
2. Windows Shadow Copies deleted using `vssadmin` (anti-recovery technique)
3. A ransom note file created on disk

This represents the classic ransomware attack pattern used by real-world families such as LockBit, Conti and Ryuk.

---

## 2. Detection Queries Used

### Query 1 — Shadow Copy Deletion
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*vssadmin*"
| table _time, Account_Name, New_Process_Name, Process_Command_Line
| sort -_time
```

### Query 2 — Refined Correlation (Final, Tuned Version)
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*vssadmin*" OR Process_Command_Line="*delete shadows*" OR Process_Command_Line="*.locked*"
| eval Indicator=case(
    match(Process_Command_Line, "vssadmin"), "Shadow Copy Deletion",
    match(Process_Command_Line, "\.locked"), "Encrypted File Extension")
| table _time, Account_Name, ComputerName, Indicator, Process_Command_Line
| sort -_time
```

---

## 3. Findings

| Time | Account | Computer | Indicator | Command |
|---|---|---|---|---|
| 15:41:34 | hp | JIMIL-JOSHI | Shadow Copy Deletion 🔴 | `vssadmin delete shadows /all /quiet` |
| 15:41:30 | hp | JIMIL-JOSHI | Shadow Copy Deletion 🔴 | `vssadmin delete shadows /all /quiet` |

**2 shadow copy deletion events confirmed** — both executed by account `hp` on host `JIMIL-JOSHI`.

---

## 4. Detection Tuning — Lesson Learned

During investigation, an initial broader query included a match condition for the substring `"ren"` to catch file rename activity. This produced **false positives**, matching unrelated processes such as Microsoft Edge WebView and WhatsApp Desktop (which contain the substring "ren" inside words like "renderer").

**Fix applied:** Removed the overly broad `"ren"` match condition and kept only high-confidence indicators (`vssadmin`, `.locked`). This is a real-world example of detection rule tuning — a core SOC analyst responsibility to reduce alert noise and false positives.

---

## 5. Detection Gap Identified

A validation query for `cmd.exe` activity in the relevant time window showed **no logged child process events** for the `echo` (ransom note creation) or `ren` (file rename) shell built-in commands used in this simulation.

**Root cause:** Windows Event ID 4688 (Process Creation) reliably logs the launch of `cmd.exe` itself, but simple shell built-ins executed inside that shell session do not always generate separate process creation events.

**Recommendation:** In a production environment, this gap should be closed using **Sysmon Event ID 11 (FileCreate)** and **Event ID 23 (FileDelete)**, or File Integrity Monitoring (FIM), to directly detect mass file rename/encryption activity rather than relying on process creation logs alone.

---

## 6. Attack Timeline

```
RANSOMWARE ATTACK CHAIN:
──────────────────────────────────────────
Step 1: Test files renamed with .locked extension
        → Simulated file encryption

Step 2: vssadmin delete shadows /all /quiet (x2)
        → Event ID 4688 ✅ DETECTED
        → Shadow copies deleted — anti-recovery technique

Step 3: Ransom note file created (README_DECRYPT.txt)
        → Not captured by Event 4688 (detection gap)
──────────────────────────────────────────
VERDICT: RANSOMWARE BEHAVIOR CONFIRMED! 🔴
```

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Impact | Data Encrypted for Impact | T1486 |
| Impact | Inhibit System Recovery | T1490 |

---

## 8. Verdict

**✅ TRUE POSITIVE — Ransomware Behavior Confirmed**

Shadow copy deletion via `vssadmin delete shadows /all /quiet` is a high-confidence ransomware indicator rarely seen in legitimate administrative activity. Combined with file rename to a `.locked` extension and ransom note creation, this confirms classic ransomware behavior on host `JIMIL-JOSHI`.

---

## 9. Recommendations

- 🔴 Isolate host from network immediately in a real incident
- 🔴 Escalate to SOC L2 / Incident Response team
- 🔴 Identify and block the initial infection vector (e.g. malicious attachment)
- 🟡 Restore files from offline/immutable backups (shadow copies were deleted)
- 🟡 Deploy Sysmon for file-level visibility (Event ID 11, 23)
- 🟢 Create a Splunk alert on any `vssadmin delete shadows` execution
- 🟢 Restrict `vssadmin.exe` execution via application allow-listing for non-admin users

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/ransomware_shadow_copy_deletion.png` | Shadow copy deletion detected — 2 events |
| `screenshots/ransomware_query_tuning.png` | Refined query removing false positives |
| `screenshots/ransomware_detection_gap.png` | Validation showing cmd.exe detection gap |
