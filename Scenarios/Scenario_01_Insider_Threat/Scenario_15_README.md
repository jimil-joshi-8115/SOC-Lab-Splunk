# Scenario 15 — Indicator Removal (Timestomping)

## 🎯 Objective
Simulate and detect timestomping — an anti-forensics technique where an attacker modifies a file's timestamp metadata to disguise its true age and disrupt forensic timeline reconstruction. The final scenario in this campaign's extended set.

## 🧩 MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Indicator Removal: Timestomp | T1070.006 |

## 🖥️ Attack Simulation

**1. Create test payload file**
```cmd
echo test payload content > C:\Users\hp\AppData\Local\Temp\suspicious_tool.exe
```

**2. Baseline timestamp check**
```powershell
powershell.exe -Command "(Get-Item C:\Users\hp\AppData\Local\Temp\suspicious_tool.exe) | Select-Object CreationTime, LastWriteTime, LastAccessTime"
```

**3. Timestomp — backdate to 2020-01-15**
```powershell
powershell.exe -Command "$file=Get-Item C:\Users\hp\AppData\Local\Temp\suspicious_tool.exe; $date=Get-Date '2020-01-15 10:00:00'; $file.CreationTime=$date; $file.LastWriteTime=$date; $file.LastAccessTime=$date"
```

**4. Verify the change**
```powershell
powershell.exe -Command "(Get-Item C:\Users\hp\AppData\Local\Temp\suspicious_tool.exe) | Select-Object CreationTime, LastWriteTime, LastAccessTime"
```

**5. Cleanup**
```cmd
del C:\Users\hp\AppData\Local\Temp\suspicious_tool.exe
```

## 🔍 Detection Queries
See [`timestomping_detection.spl`](../../SPL-Queries/timestomping_detection.spl) for the full query set.

## 📊 Key Findings
| Time | Event | Significance |
|---|---|---|
| 09:10:28 | Baseline timestamp check | Pre-modification state |
| 09:10:38 | Timestomp executed (all 3 timestamps → 2020-01-15) | T1070.006 |
| 09:10:47 / 09:11:35 | Verification checks (x2) | Post-modification confirmation |

**Real SOC lesson:** the highest-confidence indicator isn't any single timestamp field — it's that `CreationTime`, `LastWriteTime`, and `LastAccessTime` were all set to one identical, hardcoded historical value in a single command. Real files almost never have all three timestamps exactly matching, since normal OS behavior updates them independently over time.

## 🟠 Verdict
Confirmed simulated timestomping — baseline check, modification, and verification all successfully detected via native Windows process logging. This closes out the anti-forensics thread running through this campaign (Lab 08 log clearing → Scenario 02 shadow copy deletion → this scenario's timestamp manipulation).

## 📁 Related Files
- Full investigation report: [`Investigation-Reports/timestomping_IR-2026-016.md`](../../Investigation-Reports/timestomping_IR-2026-016.md)
- Formal incident report: [`Incident-Reports/IR-2026-016_Timestomping.docx`](../../Incident-Reports/IR-2026-016_Timestomping.docx)
- SPL queries: [`SPL-Queries/timestomping_detection.spl`](../../SPL-Queries/timestomping_detection.spl)
