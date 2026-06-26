# Scenario 11 — Kerberoasting

## 🎯 Objective
Simulate and detect the command-line signatures of Kerberoasting — a high-impact Active Directory credential access technique that exploits Kerberos service ticket requests for SPN-registered accounts.

## 🧩 MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 |

## ⚠️ Lab Environment Note
Real Kerberoasting requires an Active Directory domain controller, since SPNs and Kerberos ticket-granting only exist in a domain context. This lab is a standalone host without AD, so this scenario simulates only the command-line syntax of real Kerberoasting tools/techniques — no real domain, SPN, or Kerberos ticket was involved.

## 🖥️ Attack Simulation

**1. SPN enumeration**
```cmd
cmd.exe /c echo setspn.exe -T DOMAIN -Q */* > C:\Users\hp\AppData\Local\Temp\spn_enum_log.txt
```

**2. Rubeus-style ticket extraction reference**
```cmd
cmd.exe /c echo Rubeus.exe kerberoast /outfile:C:\Users\hp\AppData\Local\Temp\kerberoast_hashes.txt
```

**3. Native PowerShell Kerberos ticket request (tool-less alternative)**
```cmd
cmd.exe /c echo powershell.exe -c "Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/sql01.domain.local:1433'"
```

**4. Cleanup**
```cmd
del C:\Users\hp\AppData\Local\Temp\spn_enum_log.txt
del C:\Users\hp\AppData\Local\Temp\kerberoast_hashes.txt
```

## 🔍 Detection Queries
See [`kerberoasting_detection.spl`](../../SPL-Queries/kerberoasting_detection.spl) for the full query set.

## 📊 Key Findings
| Time | Event | Significance |
|---|---|---|
| 09:30:22 | setspn SPN enumeration | T1558.003 reconnaissance |
| 09:30:28 | Rubeus kerberoast reference | Ticket extraction tool |
| 09:30:37 | Native PowerShell Kerberos ticket request | Tool-less alternative |

**Real SOC lesson (recurring):** all three commands logged as `cmd.exe`, not the referenced tool, since each was wrapped in `echo` rather than directly invoked — the same command-wrapping pattern first seen in Scenario 09. Reinforces that detection logic must filter on command-line content, not process name alone.

## 🔴 Verdict
Confirmed simulated Kerberoasting attempt — SPN enumeration, tool-based extraction, and tool-less alternative all successfully detected via native Windows process logging.

## 📁 Related Files
- Full investigation report: [`Investigation-Reports/kerberoasting_IR-2026-012.md`](../../Investigation-Reports/kerberoasting_IR-2026-012.md)
- Formal incident report: [`Incident-Reports/IR-2026-012_Kerberoasting.docx`](../../Incident-Reports/IR-2026-012_Kerberoasting.docx)
- SPL queries: [`SPL-Queries/kerberoasting_detection.spl`](../../SPL-Queries/kerberoasting_detection.spl)
