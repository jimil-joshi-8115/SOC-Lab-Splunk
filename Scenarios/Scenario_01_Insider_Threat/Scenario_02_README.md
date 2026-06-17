# 🎯 Scenario 02 — Ransomware Detection

## Scenario Overview

| Field | Details |
|---|---|
| **Scenario Name** | Ransomware Simulation |
| **Difficulty** | Medium-High |
| **Date** | 17 June 2026 |
| **Analyst** | Jimil Joshi |
| **Tools Used** | Splunk Enterprise, Windows Event Logs |
| **MITRE ATT&CK** | T1486, T1490 |
| **Severity** | 🔴 Critical |

---

## Scenario Story

> An employee opens a malicious attachment. Within seconds, files across the system are renamed with a `.locked` extension and shadow copies are deleted to prevent recovery. A ransom note is dropped on disk. As SOC L1 analyst, detect the ransomware behavior using Splunk before it spreads further!

---

## Attack Chain Simulated

```
Step 1 → Test files created and renamed to .locked extension
Step 2 → Shadow copies deleted via vssadmin (anti-recovery)
Step 3 → Ransom note file created on disk
```

---

## Commands Used to Simulate

```cmd
REM Step 1 - Create test files
mkdir C:\TestFiles
echo test1 > C:\TestFiles\document1.txt
echo test2 > C:\TestFiles\document2.txt
echo test3 > C:\TestFiles\photo1.jpg

REM Step 2 - Simulate encryption via rename
ren C:\TestFiles\document1.txt document1.txt.locked
ren C:\TestFiles\document2.txt document2.txt.locked
ren C:\TestFiles\photo1.jpg photo1.jpg.locked

REM Step 3 - Delete shadow copies (classic ransomware technique)
vssadmin delete shadows /all /quiet

REM Step 4 - Drop ransom note
echo Your files have been encrypted! Pay ransom to recover. > C:\TestFiles\README_DECRYPT.txt
```

---

## Detection Query (Final, Tuned Version)

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

## Results

| Time | Account | Computer | Indicator | Command |
|---|---|---|---|---|
| 15:41:34 | hp | JIMIL-JOSHI | Shadow Copy Deletion 🔴 | `vssadmin delete shadows /all /quiet` |
| 15:41:30 | hp | JIMIL-JOSHI | Shadow Copy Deletion 🔴 | `vssadmin delete shadows /all /quiet` |

---

## 🎯 Detection Tuning — Real SOC Lesson

An initial broader query matched the substring `"ren"` to catch file rename activity, but this caught **false positives** from unrelated processes (Edge WebView, WhatsApp Desktop — containing "renderer" in their command lines). The query was tuned to remove this overly broad match — a real demonstration of false-positive reduction, a core SOC analyst skill.

---

## 🎯 Detection Gap Identified

Shell built-in commands (`echo`, `ren`) executed inside `cmd.exe` did not generate separate Event ID 4688 entries. This is a known limitation of process-creation-only detection. **Recommendation:** use Sysmon Event ID 11/23 or File Integrity Monitoring for full file-level visibility in production environments.

---

## Verdict

**✅ TRUE POSITIVE — Ransomware Behavior Confirmed**

Shadow copy deletion is a high-confidence ransomware indicator. Combined with file renaming and ransom note creation, this confirms classic ransomware behavior.

---

## Files in This Scenario

| File | Description |
|---|---|
| `README.md` | This file — scenario overview |
| `screenshots/ransomware_shadow_copy_deletion.png` | Clean detection — shadow copy deletion |
| `screenshots/ransomware_query_tuning.png` | Query tuning to remove false positives |
| `screenshots/ransomware_detection_gap.png` | cmd.exe validation showing detection gap |

---

## Related Files

| File | Location |
|---|---|
| SPL Query | `SPL-Queries/ransomware_detection.spl` |
| Investigation Report | `Investigation-Reports/ransomware_IR-2026-003.md` |

---

## 📄 Full Investigation Report

📄 [IR-2026-003 — Ransomware Investigation](../../Investigation-Reports/ransomware_IR-2026-003.md)

---

## Screenshot

![Ransomware Shadow Copy Deletion](screenshots/ransomware_shadow_copy_deletion.png)
