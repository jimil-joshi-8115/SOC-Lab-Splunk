# Investigation Report — Scenario 12: Scheduled Task Persistence (Remote-Trigger Variant)

## Overview

| Field | Details |
|---|---|
| **Incident ID** | IR-2026-013 |
| **Scenario** | Scheduled Task Persistence — Remote-Trigger Variant |
| **Date of Simulation** | 27 June 2026 |
| **Analyst** | Jimil Joshi |
| **Host** | JIMIL-JOSHI |
| **Primary Account** | hp |
| **Severity** | 🟠 High |
| **MITRE ATT&CK Technique** | T1053.005 |
| **Tools Used** | Splunk Enterprise (Search & Reporting), Windows Security Event Logs (Event ID 4688) |

---

## Scenario Description

This scenario extends Lab 10 (Scheduled Task Created) with a more advanced, realistic persistence pattern. Rather than a simple task creation, this scenario simulates an attacker creating a scheduled task disguised under a name closely mimicking a legitimate Windows component (`MicrosoftEdgeUpdateTaskMachine`, resembling the real `MicrosoftEdgeUpdateTaskMachineCore`), configured to trigger **at every logon** and execute a payload staged in the user's Temp directory — a combination designed to survive reboots and blend in with routine browser-update automation that most users and even some analysts would skim past.

**Simulated attack narrative:**
1. Attacker creates a scheduled task named `MicrosoftEdgeUpdateTaskMachine`, set to trigger on logon (`/sc onlogon`), pointing to a payload in `%TEMP%`.
2. Attacker verifies the task was created successfully via a query.
3. Attacker manually triggers the task once to confirm it executes correctly, rather than waiting for the next logon event.
4. (Post-simulation) The task is deleted as part of lab cleanup — the delete command was issued twice in quick succession.

---

## Investigation Steps

1. Queried Event ID 4688 (Process Creation) for `schtasks.exe` invocations containing `create`.
2. Queried Event ID 4688 for `schtasks.exe` invocations containing `run`.
3. Queried Event ID 4688 for `schtasks.exe` invocations containing `delete`.
4. Combined all `schtasks.exe` activity into a single chronological view to reconstruct the full persistence lifecycle.
5. Applied a higher-fidelity tuning filter isolating only logon-triggered tasks referencing a Temp-directory path, to demonstrate a production-realistic detection rule beyond simply matching on `schtasks.exe`.

---

## Findings

| Time | Account | Command Line | Significance |
|---|---|---|---|
| 2026-06-27 09:26:13.603 | hp | `schtasks /create /tn "MicrosoftEdgeUpdateTaskMachine" /tr "C:\Users\hp\AppData\Local\Temp\update.exe" /sc onlogon /f` | Persistence task created — disguised name, logon trigger, Temp-path payload |
| 2026-06-27 09:26:22.309 | hp | `schtasks /query /tn "MicrosoftEdgeUpdateTaskMachine"` | Verification of task creation |
| 2026-06-27 09:26:31.253 | hp | `schtasks /run /tn "MicrosoftEdgeUpdateTaskMachine"` | Manual task execution — attacker confirming the payload runs |
| 2026-06-27 09:27:04.844 | hp | `schtasks /delete /tn "MicrosoftEdgeUpdateTaskMachine" /f` | Cleanup (first delete command) |
| 2026-06-27 09:27:06.388 | hp | `schtasks /delete /tn "MicrosoftEdgeUpdateTaskMachine" /f` | Cleanup (duplicate delete command, ~1.5s later) |

**Duplicate command observation:** The delete command was issued twice within approximately 1.5 seconds. This is most consistent with a double command-entry or rapid retry during manual cleanup rather than a distinct second action, and is noted here for completeness rather than treated as a separate investigative finding.

---

## Attack Timeline

```
09:26:13  →  Scheduled task created (disguised name, onlogon trigger, Temp payload)
09:26:22  →  Task creation verified via query
09:26:31  →  Task manually executed by attacker
09:27:04  →  Task deleted (cleanup)
09:27:06  →  Duplicate delete command (cleanup retry/double-entry)
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Stage |
|---|---|---|
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence / Execution |

---

## Verdict & Analysis

This simulation successfully demonstrates a realistic, disguise-based scheduled task persistence technique, building directly on the simpler version detected in Lab 10. Detection relied on Event ID 4688 (Process Creation), filtering on `schtasks.exe` command-line content for `create`, `run`, and `delete` operations.

While filtering on the presence of `schtasks.exe` alone is useful for visibility, it would generate substantial noise in a real environment, since `schtasks` is widely used for legitimate IT automation. The higher-fidelity tuning query — isolating tasks with both an `onlogon` trigger and a `Temp` directory path — represents a meaningfully stronger detection rule, since legitimate scheduled tasks referencing user Temp folders are rare, and this combination of trigger type and target path is a strong indicator of attacker tradecraft specifically.

The use of a name closely resembling a legitimate Microsoft Edge update task (`MicrosoftEdgeUpdateTaskMachine` vs. the real `MicrosoftEdgeUpdateTaskMachineCore`) reinforces a lesson first raised in Scenario 07: persistence entries are deliberately named to blend in, and analysts should verify the referenced executable path rather than trusting a familiar-sounding task name.

**Verdict:** 🟠 Confirmed simulated scheduled task persistence — disguised task name, logon-trigger configuration, and Temp-path payload all successfully detected via Windows native process logging.

---

## Response Actions

**Immediate:**
- Investigate the legitimacy of the `update.exe` file referenced in the scheduled task action.
- Review the full Windows Task Scheduler library for any additional tasks with similarly disguised names or Temp/AppData-path actions.
- Confirm the task has been fully removed (verify via Task Scheduler GUI or `schtasks /query` in addition to the command-line evidence).

**Recommended:**
- Build a correlation rule alerting on any `schtasks /create` command containing both an `onlogon` (or similarly persistent) trigger and a path under `Temp`, `AppData`, or other non-standard install locations.
- Maintain a baseline of expected/approved scheduled tasks per host, and alert on any new task creation that doesn't match the baseline.
- Cross-reference newly created task names against known legitimate Microsoft/vendor task naming conventions to flag near-miss disguises (e.g., missing or altered suffixes like `Core`).
- Enable Windows Task Scheduler operational log auditing (Event ID 106/140/141) as a complementary, more directly task-specific evidence source alongside process-creation logging.

---

## Conclusion

Scenario 12 demonstrates detection of an advanced scheduled task persistence technique — combining a disguised task name, a logon-based trigger, and a Temp-directory payload — using native Windows Event ID 4688 logging in Splunk. The investigation captured the complete lifecycle of the technique and produced a higher-fidelity, production-style detection rule beyond simple binary-name matching, building directly on lessons from earlier scenarios in this campaign regarding disguised persistence and detection rule tuning.

---

**Investigated by:** Jimil Joshi
**Role:** SOC L1 Analyst (Simulated Lab Environment)
**Report Status:** Final
