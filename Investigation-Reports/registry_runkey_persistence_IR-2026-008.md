# Investigation Report — Scenario 07: Persistence via Registry Run Keys

## Overview

| Field | Details |
|---|---|
| **Incident ID** | IR-2026-008 |
| **Scenario** | Persistence via Registry Run Keys |
| **Date of Simulation** | 22 June 2026 |
| **Analyst** | Jimil Joshi |
| **Host** | JIMIL-JOSHI |
| **Primary Account** | hp |
| **Severity** | 🟠 High |
| **MITRE ATT&CK Technique** | T1547.001 |
| **Tools Used** | Splunk Enterprise (Search & Reporting), Windows Security Event Logs (Event ID 4688) |

---

## Scenario Description

This scenario simulates an attacker establishing **persistence** after gaining initial access to a system, by adding entries to the Windows Registry "Run" keys. Any program referenced in these keys automatically launches at user logon, making this one of the simplest and most widely abused persistence mechanisms in real-world attacks — favored for its low complexity and the fact that it does not require installing a new service (which is comparatively more visible to defenders).

**Simulated attack narrative:**
1. Attacker adds a disguised persistence entry (`WindowsUpdateChecker`) to the current user's Run key (`HKCU`), pointing to a payload in the Temp directory.
2. Attacker adds a second disguised entry (`SecurityHealthMonitor`) to the machine-wide Run key (`HKLM`), which requires administrative privileges to write.
3. Attacker verifies the persistence entries were written successfully via a registry query.
4. (Post-simulation) Both entries are removed as part of lab cleanup.

---

## Investigation Steps

1. Queried Event ID 4688 (Process Creation) for `reg.exe` invocations referencing the `CurrentVersion\Run` registry path.
2. Filtered specifically for `add` operations to identify persistence creation events.
3. Filtered for `query` operations to identify verification/reconnaissance of existing persistence.
4. Filtered for `delete` operations to identify removal/cleanup activity.
5. Combined all `reg.exe` + Run-key activity into a single chronological view to reconstruct the full persistence lifecycle.
6. Checked Event ID 4657 (registry value change auditing) as an alternate evidence source — not required in this investigation, as process-level logging (4688) fully captured the activity.

---

## Findings

| Time | Account | Command Line | Significance |
|---|---|---|---|
| 2026-06-22 20:23:20.112 | hp | `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdateChecker /t REG_SZ /d "C:\Users\hp\AppData\Local\Temp\update.exe" /f` | Persistence entry created — current user (HKCU) |
| 2026-06-22 20:23:30.758 | hp | `reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v SecurityHealthMonitor /t REG_SZ /d "C:\Users\hp\AppData\Local\Temp\update.exe" /f` | Persistence entry created — machine-wide (HKLM) |
| 2026-06-22 20:23:38.918 | hp | `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"` | Verification of persistence entry |
| 2026-06-22 20:24:19.701 | hp | `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdateChecker /f` | Persistence entry removed (cleanup) |
| 2026-06-22 20:24:21.255 | hp | `reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v SecurityHealthMonitor /f` | Persistence entry removed (cleanup) |

**Privilege observation:** The `hp` account successfully wrote to `HKLM` (machine-wide registry hive) without any "Access Denied" error. Writing to `HKLM` normally requires administrative privileges, confirming that the `hp` account is operating with local administrator rights on this host. This is a relevant finding in its own right — an attacker operating under an admin-level account has significantly more persistence options available (machine-wide Run keys, services, scheduled tasks) than one limited to a standard user context.

---

## Attack Timeline

```
20:23:20  →  Persistence entry added to HKCU Run key (WindowsUpdateChecker)
20:23:30  →  Persistence entry added to HKLM Run key (SecurityHealthMonitor)
20:23:38  →  Verification query of HKCU Run key
20:24:19  →  HKCU persistence entry removed (cleanup)
20:24:21  →  HKLM persistence entry removed (cleanup)
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Stage |
|---|---|---|
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Persistence |

---

## Verdict & Analysis

This simulation successfully demonstrates detection of one of the most common and historically significant persistence techniques used by real-world malware and attackers. The detection relied entirely on Event ID 4688 (Process Creation), filtering on `reg.exe` command lines referencing the `CurrentVersion\Run` registry path — a high-fidelity indicator, since legitimate administrative use of `reg.exe` against Run keys is uncommon outside of software installation or IT management activity.

The use of disguised, legitimate-sounding value names (`WindowsUpdateChecker`, `SecurityHealthMonitor`) mirrors real attacker tradecraft, where persistence entries are deliberately named to blend in with genuine Windows or security software processes. Analysts reviewing Run key contents should treat unfamiliar entries with suspicion regardless of how official the name sounds, and should always verify the referenced executable path and digital signature rather than trusting the display name alone.

**Verdict:** 🟠 Confirmed simulated registry-based persistence — both user-level and machine-level persistence techniques successfully detected via Windows native process logging.

---

## Response Actions

**Immediate:**
- Investigate the legitimacy of the `update.exe` file referenced in both persistence entries.
- Review the full list of current Run key entries (`HKCU` and `HKLM`) for any additional unauthorized or suspicious values.
- Confirm both persistence entries have been removed and the referenced payload deleted.

**Recommended:**
- Build a correlation rule alerting on any `reg.exe` process with `add` and `CurrentVersion\Run` (or `RunOnce`) in the command line.
- Baseline expected/approved Run key entries per host and alert on deviations.
- Restrict standard user write access to `HKLM` Run keys where feasible, and review why the `hp` account holds local admin rights if not operationally required.
- Enable Sysmon Registry Event monitoring (Event ID 12/13/14) for more direct registry-value-level visibility, supplementing process-level detection.

---

## Conclusion

Scenario 07 demonstrates detection of registry-based persistence — a foundational and still widely used attacker technique — using native Windows Event ID 4688 logging in Splunk. The investigation captured the complete lifecycle of the technique (creation, verification, and removal) and surfaced a notable privilege-level finding (HKLM write access without elevation prompts), reflecting the kind of contextual analysis expected of a SOC L1 analyst beyond simple signature matching.

---

**Investigated by:** Jimil Joshi
**Role:** SOC L1 Analyst (Simulated Lab Environment)
**Report Status:** Final
