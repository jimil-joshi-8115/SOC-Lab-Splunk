# Scenario 09 — Credential Dumping (LSASS Memory)

## 🎯 Objective
Simulate and detect attacker reconnaissance and command-line signatures associated with LSASS memory credential dumping — one of the highest-impact credential access techniques — without executing any real dumping tool or accessing actual LSASS memory.

## 🧩 MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| OS Credential Dumping: LSASS Memory | T1003.001 |

## ⚠️ Safety Note
Real LSASS dumping tools (Mimikatz, real `procdump` against LSASS) are flagged as malware and carry genuine risk even in a home lab. This scenario simulates only the command-line syntax and reconnaissance pattern — no real LSASS memory was accessed or dumped.

## 🖥️ Attack Simulation

**1. Simulated procdump-style LSASS targeting command**
```cmd
cmd.exe /c echo procdump.exe -accepteula -ma lsass.exe C:\Users\hp\AppData\Local\Temp\lsass_dump.dmp
```

**2. LSASS process reconnaissance**
```cmd
tasklist /fi "imagename eq lsass.exe"
```

**3. Cleanup**
```cmd
del C:\Users\hp\AppData\Local\Temp\cred_search_log.txt
```

## 🔍 Detection Queries
See [`credential_dumping_lsass_detection.spl`](../../SPL-Queries/credential_dumping_lsass_detection.spl) for the full query set.

## 📊 Key Findings
| Time | Event | Significance |
|---|---|---|
| 19:21:17 | Simulated procdump command targeting lsass.exe | T1003.001 |
| 19:21:25 | tasklist reconnaissance of lsass.exe | T1003.001 (precursor) |

**Real SOC lesson:** a planned `findstr`-based credential search step did not generate its own process event, since it was wrapped in `cmd.exe /c echo ...` rather than directly invoking `findstr.exe`. Documented as a simulation artifact and a reminder that command wrapping can obscure the true target process in real investigations too.

## 🔴 Verdict
Confirmed simulated credential dumping attempt — LSASS targeting and reconnaissance successfully detected via native Windows process logging.

## 📁 Related Files
- Full investigation report: [`Investigation-Reports/credential_dumping_IR-2026-010.md`](../../Investigation-Reports/credential_dumping_IR-2026-010.md)
- Formal incident report: [`Incident-Reports/IR-2026-010_Credential_Dumping.docx`](../../Incident-Reports/IR-2026-010_Credential_Dumping.docx)
- SPL queries: [`SPL-Queries/credential_dumping_lsass_detection.spl`](../../SPL-Queries/credential_dumping_lsass_detection.spl)
