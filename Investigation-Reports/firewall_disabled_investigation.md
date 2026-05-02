# 🔍 Investigation Report — Windows Firewall Disabled

## Overview

| Field | Details |
|---|---|
| **Date** | 02 May 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Event ID** | 4104 (Alternative) / 4950 (Ideal) |
| **MITRE ATT&CK** | T1562.004 — Disable or Modify System Firewall |
| **Severity** | Critical |
| **Status** | Investigated — Simulated Attack (Lab) |

---

## 1. Alert Description

Splunk detected **74 PowerShell events** (Event ID 4104) containing firewall modification commands on host `JIMIL-JOSHI`. The command `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False` was detected — confirming Windows Firewall was disabled via PowerShell.

In a real SOC environment, firewall disabling is **Critical severity** because:
- Removes network protection from the machine
- Allows attackers to communicate with C2 servers
- Enables inbound connections for backdoors and RATs
- Disabling firewall is a classic attacker defense evasion technique

---

## 2. Detection Method

### Ideal Detection — Event ID 4950
Event ID 4950 is the native Windows event for firewall setting changes. However this requires the **Windows Firewall Advanced Security** log source to be configured in Splunk.

### Alternative Detection Used — Event ID 4104
Since Event ID 4950 was not available in this lab environment, **PowerShell Script Block Logging (Event ID 4104)** was used as an alternative detection method. This captures the exact PowerShell command used to disable the firewall.

> **Note:** In a production SOC environment, both Event ID 4950 and 4104 should be monitored together for complete firewall change detection coverage.

---

## 3. Detection Query Used

```spl
index=main EventCode=4104
| search Message="*NetFirewall*" OR Message="*Enabled False*" OR Message="*Enabled True*"
| table _time, ComputerName, Message
| sort -_time
| head 20
```

---

## 4. Findings

| Time | Computer | Command Detected | Risk |
|---|---|---|---|
| 16:09:19 | JIMIL-JOSHI | `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True` | 🔴 Critical |
| 16:09:06 | JIMIL-JOSHI | PowerShell script block execution | 🟡 Medium |

- **74 total firewall-related events** detected on `JIMIL-JOSHI`
- Firewall was disabled then re-enabled — classic attacker pattern
- All Domain, Public and Private profiles were targeted

---

## 5. Timeline of Events

| Time | Event |
|---|---|
| 15:56:55 | First firewall-related PowerShell event detected |
| 16:09:06 | Firewall modification script executed |
| 16:09:19 | `Set-NetFirewallProfile -Enabled True` detected — firewall re-enabled |
| After detection | Firewall confirmed back on — system secured |

---

## 6. Analysis

Disabling Windows Firewall is a **classic attacker technique** used for:

**Defense Evasion:**
- Removes outbound connection restrictions
- Allows C2 (Command & Control) communication
- Bypasses network-based detection

**Enabling Persistence:**
- Opens ports for remote access tools (RATs)
- Allows inbound RDP connections
- Enables lateral movement to other machines

**Key Detection Insight:**
Even though Event ID 4950 was not available, PowerShell Script Block Logging caught the exact command used. This demonstrates the importance of **layered detection** — if one log source fails, another can compensate.

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Defense Evasion | Impair Defenses | T1562 |
| Defense Evasion | Disable or Modify System Firewall | T1562.004 |

---

## 8. Conclusion

Splunk successfully detected the Windows Firewall modification via PowerShell Script Block Logging. Although the ideal Event ID 4950 was not available, the alternative detection method captured the exact command used — demonstrating effective layered detection strategy.

**Verdict: True Positive — Firewall Disabled via PowerShell Detected ✅**

---

## 9. Recommendations

- Configure Windows Firewall Advanced Security logs in Splunk for Event ID 4950
- Monitor both Event ID 4950 AND 4104 for complete firewall change detection
- Alert immediately on any `Set-NetFirewallProfile -Enabled False` command
- Alert on `netsh advfirewall set` commands in process creation logs (4688)
- Restrict who can modify firewall settings via Group Policy
- Consider using Windows Defender Firewall with Advanced Security for granular control

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/20_firewall_commands_detected.png` | PowerShell firewall commands detected in Splunk |
| `screenshots/21_firewall_stats_table.png` | Stats showing 74 events on JIMIL-JOSHI |
