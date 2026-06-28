# Investigation Report — Scenario 13: Clipboard & Screen Capture Collection

## Overview

| Field | Details |
|---|---|
| **Incident ID** | IR-2026-014 |
| **Scenario** | Clipboard & Screen Capture Collection |
| **Date of Simulation** | 27 June 2026 |
| **Analyst** | Jimil Joshi |
| **Host** | JIMIL-JOSHI |
| **Primary Account** | hp |
| **Severity** | 🟠 High |
| **MITRE ATT&CK Techniques** | T1115, T1113 |
| **Tools Used** | Splunk Enterprise (Search & Reporting), Windows Security Event Logs (Event ID 4688) |

---

## Scenario Description

This scenario simulates a **data collection** stage that, in a real attack chain, would typically occur before staging and exfiltration (as detected in Scenario 04). Rather than searching the file system for sensitive documents, this technique captures information passively and continuously: clipboard contents (catching anything a user copies, such as passwords or sensitive text) and periodic screenshots (capturing on-screen information, including content never saved to disk). Both techniques are quiet, generate small output files, and are commonly used as an early, low-effort collection method.

**Simulated attack narrative:**
1. Attacker captures current clipboard contents using PowerShell's native `Get-Clipboard` cmdlet, writing the result to a file in the Temp directory.
2. Attacker captures a screenshot of the primary display using a .NET `System.Drawing.Bitmap` / `CopyFromScreen` method, saved to Temp.
3. Attacker captures a second screenshot approximately 9 seconds later, demonstrating a repeated/periodic capture pattern rather than a single one-off screenshot.

---

## Investigation Steps

1. Queried Event ID 4688 (Process Creation) for PowerShell invocations containing `Get-Clipboard`.
2. Queried Event ID 4688 for PowerShell invocations containing `CopyFromScreen`.
3. Aggregated screen capture events by account, counting occurrences and capturing the earliest/latest timestamps, to specifically identify repeated capture behavior rather than a single screenshot.
4. Combined clipboard and screen capture indicators into a single chronological view to reconstruct the full collection activity chain.

---

## Findings

| Time | Account | Command Line (abbreviated) | Significance |
|---|---|---|---|
| 2026-06-27 22:38:07.660 | hp | `Get-Clipboard \| Out-File ...\Temp\clipboard_dump.txt` | Clipboard data collection (T1115) |
| 2026-06-27 22:38:20.656 | hp | `...CopyFromScreen(0,0,0,0,$b.Size); $b.Save('...\Temp\screen_capture.png')` | First screen capture (T1113) |
| 2026-06-27 22:38:29.615 | hp | `...CopyFromScreen(0,0,0,0,$b.Size); $b.Save('...\Temp\screen_capture2.png')` | Second screen capture (T1113), ~9 seconds later |

**Aggregated detection result:** 2 screen capture events for account `hp` within a single 60-minute window, with first and last capture approximately 9 seconds apart. This confirms a `capture_count >= 2` pattern, which is a materially stronger indicator of automated/scripted collection behavior than a single screenshot, since a single capture event alone could plausibly originate from ordinary user activity (e.g., a manual PrintScreen press).

---

## Attack Timeline

```
22:38:07  →  Clipboard contents captured and written to file (T1115)
22:38:20  →  First screen capture saved (T1113)
22:38:29  →  Second screen capture saved, ~9 seconds later (T1113 — periodic pattern)
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Stage |
|---|---|---|
| T1115 | Clipboard Data | Collection |
| T1113 | Screen Capture | Collection |

---

## Verdict & Analysis

This simulation successfully demonstrates detection of two common, low-effort collection techniques using native Windows Event ID 4688 logging, filtering on PowerShell command-line content referencing `Get-Clipboard` and `CopyFromScreen`. Both are reasonably high-fidelity indicators in isolation, since legitimate business use of either cmdlet/method directly via command-line PowerShell (rather than within an approved internal tool) is uncommon.

The more analytically interesting result here is the aggregation-based detection in Query 3: rather than simply flagging the presence of `CopyFromScreen`, counting occurrences per account within a time window distinguishes a single incidental capture from a repeated, automated pattern consistent with deliberate surveillance/collection behavior. This is a meaningfully different and more robust detection approach than simple keyword matching, and is broadly applicable to other "low-and-slow" collection or reconnaissance techniques beyond this specific scenario.

**Verdict:** 🟠 Confirmed simulated clipboard and screen capture collection — both techniques successfully detected, with the repeated screen-capture pattern providing additional confidence via aggregation-based analysis.

---

## Response Actions

**Immediate:**
- Investigate the source of the `Get-Clipboard` and `CopyFromScreen` invocations tied to the `hp` account.
- Review the contents of any clipboard dump or screen capture files found on the host, and determine what sensitive information, if any, was captured.
- Check for any subsequent staging or exfiltration activity (e.g., compression or network transfer of the captured files), consistent with the broader collection-then-exfiltration kill chain.

**Recommended:**
- Build a correlation rule alerting on PowerShell command lines referencing `Get-Clipboard`, `CopyFromScreen`, or `System.Drawing.Bitmap`, particularly from non-administrative or unexpected processes.
- Specifically alert on repeated screen capture events (2 or more within a short window) per account, using aggregation logic similar to Query 3, since this is a stronger signal than any single capture event.
- Enable PowerShell Script Block Logging (Event ID 4104) to capture the full script content for any matching events, supplementing command-line visibility from Event ID 4688.
- Consider Data Loss Prevention (DLP) tooling with clipboard monitoring capability for environments handling highly sensitive data, as an additional layer beyond log-based detection.

---

## Conclusion

Scenario 13 demonstrates detection of clipboard and screen capture collection — two quiet, low-effort techniques that typically precede staging and exfiltration in a real attack chain — using native Windows Event ID 4688 logging in Splunk. The investigation introduced an aggregation-based detection approach (counting repeated captures per account) that meaningfully strengthens confidence beyond simple keyword matching, reflecting the kind of detection engineering judgment expected of a SOC L1 analyst progressing toward more advanced analytical work.

---

**Investigated by:** Jimil Joshi
**Role:** SOC L1 Analyst (Simulated Lab Environment)
**Report Status:** Final
