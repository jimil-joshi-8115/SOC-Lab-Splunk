# Scenario 14 — Command & Control via DNS/HTTP Beaconing

## 🎯 Objective
Simulate and detect C2 beaconing — periodic, low-volume check-ins from a malware implant to a remote C2 server — distinct from the burst-style DNS tunneling exfiltration detected in Scenario 04.

## 🧩 MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Application Layer Protocol: DNS | T1071.004 |
| Application Layer Protocol: Web Protocols | T1071.001 |

## 🖥️ Attack Simulation

**1–3. DNS beacon check-ins (repeated, roughly spaced)**
```cmd
nslookup c2-checkin.example.com
```

**4. HTTP beacon check-in (alternate C2 channel)**
```cmd
powershell.exe -Command "Invoke-WebRequest -Uri 'https://example.com/checkin' -UseBasicParsing -ErrorAction SilentlyContinue"
```

No cleanup required — neither command creates files or persistent changes.

## 🔍 Detection Queries
See [`c2_beaconing_detection.spl`](../../SPL-Queries/c2_beaconing_detection.spl) for the full query set, including the time-delta calculation query used to assess interval regularity.

## 📊 Key Findings
| Time | Event | Gap from Previous |
|---|---|---|
| 14:53:23 | DNS beacon #1 | — |
| 14:53:28 | DNS beacon #2 | ~4.7s |
| 14:53:49 | DNS beacon #3 | ~21.3s |
| 14:54:21 | HTTP beacon | ~31.2s |

**Real SOC lesson (honestly documented):** the manually-triggered check-ins here are *not* perfectly regular — real beaconing detection relies on **low jitter/variance** between intervals, not just repetition. This simulation correctly demonstrates the detection queries and analytical approach, but doesn't itself produce the tight, low-jitter pattern a real automated implant would show. Documented transparently as a simulation limitation rather than overstating the result.

## 🔴 Verdict
Confirmed simulated C2 beaconing pattern across both DNS and HTTP channels — detection approach correctly applied, with an honest limitation noted regarding manually-simulated interval regularity.

## 📁 Related Files
- Full investigation report: [`Investigation-Reports/c2_beaconing_IR-2026-015.md`](../../Investigation-Reports/c2_beaconing_IR-2026-015.md)
- Formal incident report: [`Incident-Reports/IR-2026-015_C2_Beaconing.docx`](../../Incident-Reports/IR-2026-015_C2_Beaconing.docx)
- SPL queries: [`SPL-Queries/c2_beaconing_detection.spl`](../../SPL-Queries/c2_beaconing_detection.spl)
