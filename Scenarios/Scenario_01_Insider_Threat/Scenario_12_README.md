# Scenario 12 — Scheduled Task Persistence (Remote-Trigger Variant)

## 🎯 Objective
Simulate and detect an advanced scheduled task persistence technique — a disguised task name, logon-based trigger, and Temp-directory payload — extending beyond the simpler version in Lab 10.

## 🧩 MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Scheduled Task/Job: Scheduled Task | T1053.005 |

## 🖥️ Attack Simulation

**1. Create disguised persistence task (logon trigger)**
```cmd
schtasks /create /tn "MicrosoftEdgeUpdateTaskMachine" /tr "C:\Users\hp\AppData\Local\Temp\update.exe" /sc onlogon /f
```

**2. Verify task creation**
```cmd
schtasks /query /tn "MicrosoftEdgeUpdateTaskMachine"
```

**3. Manually trigger the task**
```cmd
schtasks /run /tn "MicrosoftEdgeUpdateTaskMachine"
```

**4. Cleanup**
```cmd
schtasks /delete /tn "MicrosoftEdgeUpdateTaskMachine" /f
```

## 🔍 Detection Queries
See [`scheduled_task_persistence_detection.spl`](../../SPL-Queries/scheduled_task_persistence_detection.spl) for the full query set, including a higher-fidelity tuning query isolating logon-triggered tasks pointing to Temp paths.

## 📊 Key Findings
| Time | Event | Significance |
|---|---|---|
| 09:26:13 | Task created — disguised name, onlogon trigger, Temp payload | T1053.005 |
| 09:26:22 | Task creation verified | Reconnaissance/verification |
| 09:26:31 | Task manually executed | Attacker confirming payload runs |
| 09:27:04 / 09:27:06 | Task deleted (issued twice) | Cleanup |

**Real SOC lesson:** filtering on `schtasks.exe` alone is too noisy for production use, since it's widely used for legitimate automation. A stronger rule combines the `onlogon` trigger with a `Temp`-path target — a combination rarely seen in legitimate task configurations. The disguised task name (`MicrosoftEdgeUpdateTaskMachine` vs. the real `MicrosoftEdgeUpdateTaskMachineCore`) also reinforces the naming-disguise lesson first seen in Scenario 07.

## 🟠 Verdict
Confirmed simulated scheduled task persistence — disguised name, logon trigger, and Temp-path payload all successfully detected via native Windows process logging.

## 📁 Related Files
- Full investigation report: [`Investigation-Reports/scheduled_task_persistence_IR-2026-013.md`](../../Investigation-Reports/scheduled_task_persistence_IR-2026-013.md)
- Formal incident report: [`Incident-Reports/IR-2026-013_Scheduled_Task_Persistence.docx`](../../Incident-Reports/IR-2026-013_Scheduled_Task_Persistence.docx)
- SPL queries: [`SPL-Queries/scheduled_task_persistence_detection.spl`](../../SPL-Queries/scheduled_task_persistence_detection.spl)
