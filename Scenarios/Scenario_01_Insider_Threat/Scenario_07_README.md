# Scenario 07 — Persistence via Registry Run Keys

## 🎯 Objective
Simulate and detect attacker persistence established via Windows Registry "Run" keys — one of the most common and historically significant autostart-based persistence techniques.

## 🧩 MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 |

## 🖥️ Attack Simulation

**1. Add persistence entry — current user (HKCU)**
```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdateChecker /t REG_SZ /d "C:\Users\hp\AppData\Local\Temp\update.exe" /f
```

**2. Add persistence entry — machine-wide (HKLM, requires admin)**
```cmd
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v SecurityHealthMonitor /t REG_SZ /d "C:\Users\hp\AppData\Local\Temp\update.exe" /f
```

**3. Verify persistence entry**
```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

**4. Cleanup (post-simulation)**
```cmd
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdateChecker /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v SecurityHealthMonitor /f
```

## 🔍 Detection Queries
See [`registry_runkey_persistence_detection.spl`](../../SPL-Queries/registry_runkey_persistence_detection.spl) for the full query set, covering add/query/delete operations and the combined full-lifecycle view.

## 📊 Key Findings
| Time | Event | Significance |
|---|---|---|
| 20:23:20 | HKCU Run key entry added | Persistence (user-level) |
| 20:23:30 | HKLM Run key entry added | Persistence (machine-wide) |
| 20:23:38 | Run key queried | Verification |
| 20:24:19 / 20:24:21 | Both entries deleted | Cleanup |

**Real SOC lesson:** the `hp` account successfully wrote to `HKLM` without elevation prompts, confirming local admin rights — a relevant finding, since admin-level access significantly expands an attacker's available persistence options.

## 🟠 Verdict
Confirmed simulated registry-based persistence — both user-level and machine-level techniques successfully detected via native Windows process logging.

## 📁 Related Files
- Full investigation report: [`Investigation-Reports/registry_runkey_persistence_IR-2026-008.md`](../../Investigation-Reports/registry_runkey_persistence_IR-2026-008.md)
- Formal incident report: [`Incident-Reports/IR-2026-008_Registry_Persistence.docx`](../../Incident-Reports/IR-2026-008_Registry_Persistence.docx)
- SPL queries: [`SPL-Queries/registry_runkey_persistence_detection.spl`](../../SPL-Queries/registry_runkey_persistence_detection.spl)
