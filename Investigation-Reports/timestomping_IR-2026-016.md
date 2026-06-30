# Investigation Report — Scenario 15: Indicator Removal (Timestomping)

## Overview

| Field | Details |
|---|---|
| **Incident ID** | IR-2026-016 |
| **Scenario** | Indicator Removal — Timestomping |
| **Date of Simulation** | 30 June 2026 |
| **Analyst** | Jimil Joshi |
| **Host** | JIMIL-JOSHI |
| **Primary Account** | hp |
| **Severity** | 🟠 High |
| **MITRE ATT&CK Technique** | T1070.006 |
| **Tools Used** | Splunk Enterprise (Search & Reporting), Windows Security Event Logs (Event ID 4688) |

---

## Scenario Description

This scenario simulates **timestomping** — an anti-forensics technique in which an attacker modifies a file's timestamp metadata (creation, last write, and last access times) to make a malicious file appear older and more legitimate, or to disrupt an investigator's ability to reconstruct an accurate forensic timeline. This is the final scenario in this campaign's extended set, and ties directly back to the anti-forensics theme first introduced in Lab 08 (Log Clearing) and Scenario 02 (Ransomware's shadow copy deletion) — the underlying goal (hide evidence of compromise) is consistent across the campaign, even as the specific mechanism varies.

**Simulated attack narrative:**
1. A test file representing a malicious payload is created in the Temp directory.
2. Its real (current) timestamps are checked first, establishing a baseline.
3. The file's `CreationTime`, `LastWriteTime`, and `LastAccessTime` properties are overwritten via PowerShell to a backdated value of `2020-01-15 10:00:00`, simulating an attacker disguising a recently-dropped file as years old.
4. The timestamps are checked again to confirm the modification succeeded.

---

## Investigation Steps

1. Queried Event ID 4688 (Process Creation) for PowerShell command lines referencing both `CreationTime` and `LastWriteTime` together, to isolate the timestomp modification action specifically.
2. Queried Event ID 4688 for PowerShell command lines combining `Get-Item` and `CreationTime`, to capture the baseline and verification check commands surrounding the modification.
3. Combined all timestamp-property-referencing PowerShell activity into a single chronological view to reconstruct the full timestomping lifecycle: baseline check, modification, and verification.

---

## Findings

| Time | Account | Command Line | Significance |
|---|---|---|---|
| 2026-06-30 09:10:28.252 | hp | `(Get-Item ...\suspicious_tool.exe) \| Select-Object CreationTime, LastWriteTime, LastAccessTime` | Baseline timestamp check (before modification) |
| 2026-06-30 09:10:38.970 | hp | `$file=Get-Item ...; $date=Get-Date '2020-01-15 10:00:00'; $file.CreationTime=$date; $file.LastWriteTime=$date; $file.LastAccessTime=$date` | Timestomp executed — all three timestamps overwritten to 2020-01-15 |
| 2026-06-30 09:10:47.202 | hp | `(Get-Item ...\suspicious_tool.exe) \| Select-Object CreationTime, LastWriteTime, LastAccessTime` | Verification check (immediately after modification) |
| 2026-06-30 09:11:35.900 | hp | `(Get-Item ...\suspicious_tool.exe) \| Select-Object CreationTime, LastWriteTime, LastAccessTime` | Second verification check, ~48 seconds later |

**Evidence scope note:** This investigation relies on command-line evidence (Event ID 4688) demonstrating that all three timestamp properties were explicitly targeted and set to a single, identical backdated value (`2020-01-15 10:00:00`) — a pattern strongly inconsistent with normal file activity, where creation, modification, and access times are virtually never identical and almost never set programmatically in this manner. This command-line evidence alone is sufficient to identify the technique, independent of directly observing the file's resulting timestamp values via the filesystem itself.

---

## Attack Timeline

```
09:10:28  →  Baseline timestamp check (file shows real/current dates)
09:10:38  →  Timestomp executed — CreationTime, LastWriteTime, LastAccessTime all set to 2020-01-15
09:10:47  →  Verification check (immediately following modification)
09:11:35  →  Second verification check (~48 seconds later)
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Stage |
|---|---|---|
| T1070.006 | Indicator Removal: Timestomp | Defense Evasion |

---

## Verdict & Analysis

This simulation successfully demonstrates detection of timestomping using native Windows Event ID 4688 logging, filtering on PowerShell command lines that explicitly reference and assign values to `CreationTime`, `LastWriteTime`, and `LastAccessTime` together. This combination is a high-fidelity indicator: legitimate administrative or development workflows rarely set all three timestamp properties to an identical, hardcoded historical date via direct PowerShell object property assignment.

This scenario completes the anti-forensics thread that has run throughout this campaign: Lab 08 detected an attacker clearing security logs to remove evidence of their activity, Scenario 02 detected shadow copy deletion to prevent file recovery, and this scenario detects an attacker manipulating file metadata to mislead timeline-based forensic analysis. Recognizing this pattern — that defense evasion is rarely a single action but rather a recurring attacker *goal* pursued through varying *mechanisms* depending on what's available — is a meaningful analytical takeaway that extends beyond any single technique.

**Verdict:** 🟠 Confirmed simulated timestomping — baseline check, timestamp modification, and verification all successfully detected via Windows native process logging.

---

## Response Actions

**Immediate:**
- Investigate the legitimacy of `suspicious_tool.exe` and confirm whether it (or any similarly-named file) still exists with manipulated timestamps on the host.
- Review the file's actual current timestamp values directly via the filesystem to confirm the backdating took effect as the command-line evidence suggests.
- Cross-reference the file's true creation time (as logged via Event ID 4688 process creation, or Sysmon Event ID 11 file creation, if available) against its now-falsified `CreationTime` property to identify the discrepancy.

**Recommended:**
- Build a correlation rule alerting on any PowerShell command line that assigns values to two or more of `CreationTime`, `LastWriteTime`, or `LastAccessTime` in the same command.
- Deploy Sysmon Event ID 2 (FileCreationTime changed) for direct, purpose-built timestomping detection, which is a stronger and more specific evidence source than process-creation command-line matching alone.
- When conducting forensic timeline analysis, treat file timestamps as corroborating evidence only, and prioritize process-creation and event-log timestamps (which are not directly attacker-modifiable via the same mechanism) as the primary source of truth.
- Train analysts to recognize the broader defense evasion pattern (log clearing, shadow copy deletion, timestomping) as variations of the same underlying attacker goal, rather than treating each as an isolated technique.

---

## Conclusion

Scenario 15 demonstrates detection of timestomping — a defense evasion technique used to disguise file age and disrupt forensic timeline reconstruction — using native Windows Event ID 4688 logging in Splunk. As the final scenario in this campaign's extended set, this investigation closes out a recurring anti-forensics thread spanning log clearing, shadow copy deletion, and now timestamp manipulation, reflecting the broader pattern-recognition and analytical synthesis expected of a SOC L1 analyst across a sustained body of investigative work.

---

**Investigated by:** Jimil Joshi
**Role:** SOC L1 Analyst (Simulated Lab Environment)
**Report Status:** Final
