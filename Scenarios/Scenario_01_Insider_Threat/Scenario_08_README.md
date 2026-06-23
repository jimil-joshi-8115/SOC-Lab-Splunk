# Scenario 08 — Defense Evasion: AV/Firewall Tampering

## 🎯 Objective
Simulate and detect attacker attempts to impair host security controls — Windows Defender real-time protection and Windows Firewall — a common defense evasion step taken before deploying further malicious payloads.

## 🧩 MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Impair Defenses: Disable or Modify Tools | T1562.001 |

## 🖥️ Attack Simulation

**1. Disable Windows Defender real-time protection**
```powershell
powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
```

**2. Disable Windows Firewall (all profiles)**
```cmd
netsh advfirewall set allprofiles state off
```

**3. Cleanup — re-enable both**
```powershell
powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $false"
```
```cmd
netsh advfirewall set allprofiles state on
```

## 🔍 Detection Queries
See [`av_firewall_tampering_detection.spl`](../../SPL-Queries/av_firewall_tampering_detection.spl) for the full query set, covering disable detection, re-enablement verification, and the combined full-lifecycle view.

## 📊 Key Findings
| Time | Event | Significance |
|---|---|---|
| 09:21:55 | Defender real-time protection disabled | Defense evasion (T1562.001) |
| 09:22:08 | Windows Firewall disabled (all profiles) | Defense evasion (T1562.001) |
| 09:22:26 | Defender re-enabled | Cleanup |
| 09:22:41 | Firewall re-enabled | Cleanup |

**Real SOC lesson:** the Defender-disable command executed with no Tamper Protection block or error — confirming Tamper Protection is not enforced on this host. Flagged as a standalone security gap, separate from the simulated attacker action itself.

## 🔴 Verdict
Confirmed simulated defense evasion — both AV and firewall tampering successfully detected, with a Tamper Protection enforcement gap identified as a secondary finding.

## 📁 Related Files
- Full investigation report: [`Investigation-Reports/defense_evasion_av_tampering_IR-2026-009.md`](../../Investigation-Reports/defense_evasion_av_tampering_IR-2026-009.md)
- Formal incident report: [`Incident-Reports/IR-2026-009_AV_Firewall_Tampering.docx`](../../Incident-Reports/IR-2026-009_AV_Firewall_Tampering.docx)
- SPL queries: [`SPL-Queries/av_firewall_tampering_detection.spl`](../../SPL-Queries/av_firewall_tampering_detection.spl)
