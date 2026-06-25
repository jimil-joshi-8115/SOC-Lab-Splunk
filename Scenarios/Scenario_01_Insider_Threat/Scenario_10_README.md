# Scenario 10 — Password Spray

## 🎯 Objective
Simulate and detect a password spray attack — an attacker attempting a small number of password guesses across many different accounts to evade per-account lockout policies, in contrast to the single-account brute force technique detected in Lab 01.

## 🧩 MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Brute Force: Password Spraying | T1110.003 |

## 🖥️ Attack Simulation

**1–4. Failed authentication attempts against four distinct local accounts (via `runas`, wrong password each time)**
```cmd
runas /user:hp1 "cmd.exe"
runas /user:hp2 "cmd.exe"
runas /user:administrator "cmd.exe"
runas /user:guest "cmd.exe"
```
All four run in quick succession (within ~1–2 minutes) to mimic automated spray tooling.

## 🔍 Detection Queries
See [`password_spray_detection.spl`](../../SPL-Queries/password_spray_detection.spl) for the full query set, including the corrected time-bucket/distinct-account grouping logic and a direct comparison note against Lab 01's brute-force detection approach.

## 📊 Key Findings
| Time | Account Targeted | Result |
|---|---|---|
| 19:24:05 | hp1 | Failed — bad password |
| 19:24:14 | hp2 | Failed — bad password |
| 19:24:27 | administrator | Failed — bad password |
| 19:25:13 | guest | Failed — bad password |

**5 distinct accounts, 4 failed attempts, within ~68 seconds** — classic password spray signature.

**Real SOC lesson:** an initial detection query grouped by `Caller_Computer_Name` returned zero results, since local `runas` attempts don't populate that field (only network logons do). Corrected by grouping on time bucket + distinct account count instead — a reminder that detection logic must match how the specific logon method actually populates event fields.

## 🟠 Verdict
Confirmed simulated password spray attack — multiple distinct accounts targeted within a single short window, successfully detected via Windows native failed-logon logging. This scenario also contrasts directly with Lab 01's brute-force detection: same Event ID (4625), inverted grouping logic (by account vs. by time window).

## 📁 Related Files
- Full investigation report: [`Investigation-Reports/password_spray_IR-2026-011.md`](../../Investigation-Reports/password_spray_IR-2026-011.md)
- Formal incident report: [`Incident-Reports/IR-2026-011_Password_Spray.docx`](../../Incident-Reports/IR-2026-011_Password_Spray.docx)
- SPL queries: [`SPL-Queries/password_spray_detection.spl`](../../SPL-Queries/password_spray_detection.spl)
